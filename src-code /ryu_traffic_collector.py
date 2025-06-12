from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
import logging
import logging.handlers
import pandas as pd
import os
import threading
import time

# Cấu hình logging
log_dir = "/home/kieungan/DDoS_Detection_SDN/logs/"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = "/home/kieungan/DDoS_Detection_SDN/logs/ryu_collector.log"
if os.path.exists(log_file):
    os.remove(log_file)

logger = logging.getLogger('ryu_traffic_collector')
logger.setLevel(logging.DEBUG)

file_handler = logging.handlers.RotatingFileHandler(
    log_file,
    maxBytes=10*1024*1024,
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_formatter = logging.Formatter('%(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Thư mục lưu trữ dữ liệu
data_dir = "/home/kieungan/DDoS_Detection_SDN/data/processed/"
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

traffic_file = os.path.join(data_dir, "live_traffic.csv")

# Tạo file với header nếu chưa tồn tại
if not os.path.exists(traffic_file):
    pd.DataFrame(columns=['src_ip', 'dst_ip', 'protocol', 'length', 'src_port', 'dst_port', 'label']).to_csv(traffic_file, index=False)
else:
    with open(traffic_file, 'r') as f:
        first_line = f.readline().strip()
        expected_header = "src_ip,dst_ip,protocol,length,src_port,dst_port,label"
        if first_line != expected_header:
            df = pd.read_csv(traffic_file, header=None, names=['src_ip', 'dst_ip', 'protocol', 'length', 'src_port', 'dst_port', 'label'])
            df.to_csv(traffic_file, index=False)

class TrafficCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficCollector, self).__init__(*args, **kwargs)
        self.packet_count = 0
        self.mac_to_port = {}
        self.traffic_buffer = []
        self.buffer_flush_interval = 0.5
        self.buffer_max_size = 1000
        self.last_flush_time = time.time()
        self.whitelist_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.11']
        self.attack_ips = ['10.0.0.6', '10.0.0.7', '10.0.0.8', '10.0.0.9', '10.0.0.10']
        self.label_counts = {'normal': 0, 'attack': 0}
        self.tolerance = 100  # Dung sai cho phép chênh lệch nhãn
        self._start_flush_thread()
        logger.info(f"Starting TrafficCollector with output file: {traffic_file}")

    def _start_flush_thread(self):
        def flush_buffer():
            while True:
                current_time = time.time()
                if (current_time - self.last_flush_time >= self.buffer_flush_interval or len(self.traffic_buffer) >= self.buffer_max_size) and self.traffic_buffer:
                    try:
                        df = pd.DataFrame(self.traffic_buffer)
                        df.to_csv(traffic_file, mode='a', header=False, index=False)
                        logger.info(f"Đã ghi {len(self.traffic_buffer)} gói tin vào {traffic_file}. Label 0: {self.label_counts['normal']}, Label 1: {self.label_counts['attack']}")
                        self.traffic_buffer = []
                        self.last_flush_time = current_time
                    except Exception as e:
                        logger.error(f"Lỗi khi ghi dữ liệu vào {traffic_file}: {e}")
                time.sleep(0.1)
        threading.Thread(target=flush_buffer, daemon=True).start()

    def balance_labels(self, feature):
        # Kiểm tra nhãn và cập nhật bộ đếm
        label = feature['label']
        if label == 0:
            if self.label_counts['normal'] <= self.label_counts['attack'] + self.tolerance:
                self.label_counts['normal'] += 1
                logger.debug(f"Thêm gói tin bình thường. Label 0: {self.label_counts['normal']}, Label 1: {self.label_counts['attack']}")
                return True
            logger.debug(f"Bỏ qua gói tin bình thường để cân bằng nhãn: {feature}. Label 0: {self.label_counts['normal']}, Label 1: {self.label_counts['attack']}")
            return False
        else:
            if self.label_counts['attack'] <= self.label_counts['normal'] + self.tolerance:
                self.label_counts['attack'] += 1
                logger.debug(f"Thêm gói tin tấn công. Label 0: {self.label_counts['normal']}, Label 1: {self.label_counts['attack']}")
                return True
            logger.debug(f"Bỏ qua gói tin tấn công để cân bằng nhãn: {feature}. Label 0: {self.label_counts['normal']}, Label 1: {self.label_counts['attack']}")
            self.label_counts['attack'] -= 1
            return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=40,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        logger.info(f"Switch {datapath.id} connected. Gửi tất cả gói IPv4 lên controller với độ ưu tiên 40.")

        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        logger.info(f"Installed ARP flood flow on switch {datapath.id}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            logger.debug("Bỏ qua gói tin không có Ethernet header")
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            logger.info(f"Nhận được gói ARP: src_ip={arp_pkt.src_ip}, dst_ip={arp_pkt.dst_ip}")
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][eth.src] = in_port

            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            logger.debug("Gói tin không phải IPv4, bỏ qua.")
            return

        self.packet_count += 1
        logger.debug(f"Đã thu thập gói tin thứ {self.packet_count} từ {ip.src} đến {ip.dst}")

        feature = {
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'protocol': ip.proto,
            'length': len(msg.data),
            'src_port': 0,
            'dst_port': 0,
            'label': 0 if ip.src in self.whitelist_ips else 1
        }

        traffic_type = "Không xác định"
        if ip.src in self.whitelist_ips:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt:
                traffic_type = "ICMP"
            elif tcp_pkt:
                if tcp_pkt.dst_port == 80:
                    traffic_type = "HTTP"
                elif tcp_pkt.dst_port == 5001:
                    traffic_type = "TCP (iperf)"
                else:
                    traffic_type = "TCP"
                feature['src_port'] = tcp_pkt.src_port
                feature['dst_port'] = tcp_pkt.dst_port
            elif udp_pkt:
                if udp_pkt.dst_port == 5001:
                    traffic_type = "UDP (iperf)"
                else:
                    traffic_type = "UDP"
                feature['src_port'] = udp_pkt.src_port
                feature['dst_port'] = udp_pkt.dst_port
            logger.info(f"Thu thập lưu lượng bình thường từ {ip.src} ({traffic_type}): {feature}")
        else:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if tcp_pkt and tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
                traffic_type = "SYN flood"
                feature['src_port'] = tcp_pkt.src_port
                feature['dst_port'] = tcp_pkt.dst_port
            elif udp_pkt:
                traffic_type = "UDP flood"
                feature['src_port'] = udp_pkt.src_port
                feature['dst_port'] = udp_pkt.dst_port
            elif icmp_pkt:
                traffic_type = "ICMP flood"
            logger.info(f"Thu thập lưu lượng tấn công từ {ip.src} ({traffic_type}): {feature}")

        # Cân bằng nhãn
        if self.balance_labels(feature):
            self.traffic_buffer.append(feature)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip.src, ipv4_dst=ip.dst)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 5, match, actions)
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)
        logger.info(f"Đã thêm flow rule cho {match} với hành động {actions}")
