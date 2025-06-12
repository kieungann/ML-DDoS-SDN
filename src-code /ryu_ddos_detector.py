from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
import logging
import os
import pandas as pd
import pickle
import time
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
import threading

# Cấu hình logging
log_dir = "/home/kieungan/DDoS_Detection_SDN/logs/"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logger = logging.getLogger('DDoSDetector')
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("/home/kieungan/DDoS_Detection_SDN/logs/ryu_detector.log")
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Thư mục lưu trữ kết quả
results_dir = "/home/kieungan/DDoS_Detection_SDN/results/"
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

comparison_report_path = os.path.join(results_dir, "comparison_report.txt")

# Tải mô hình và scaler
models_dir = "/home/kieungan/DDoS_Detection_SDN/models/"
try:
    with open(os.path.join(models_dir, "rf_model.pkl"), "rb") as f:
        rf_model = pickle.load(f)
    with open(os.path.join(models_dir, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
except Exception as e:
    logger.error(f"Không thể tải mô hình hoặc scaler: {e}")
    raise e

class DDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.blocked_ips = {}
        self.block_duration = 60
        self.packet_counts = defaultdict(lambda: {'syn': 0, 'udp': 0, 'icmp': 0})
        self.window_duration = 5
        self.last_reset = time.time()
        self.syn_threshold = 100  # Giữ nhưng không dùng
        self.udp_threshold = 50   # Giữ nhưng không dùng
        self.icmp_threshold = 20  # Giữ nhưng không dùng
        self.grace_period = 5
        self.whitelist_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.11']
        self.attack_ips = ['10.0.0.6', '10.0.0.7', '10.0.0.8', '10.0.0.9', '10.0.0.10']
        self.server_ip = '10.0.0.11'
        logger.info("Khởi động ứng dụng DDoSDetector...")
        self.compare_models()  # Giữ so sánh thuật toán
        time.sleep(45)  # Tăng độ trễ để Ryu sẵn sàng
        logger.info("Ứng dụng DDoSDetector sẵn sàng kết nối switch.")
        self.unblock_thread = threading.Thread(target=self.periodic_unblock, daemon=True)
        self.unblock_thread.start()

    def periodic_unblock(self):
        while True:
            self.unblock_expired_ips()
            time.sleep(5)

    def compare_models(self):
        try:
            logger.info("Bắt đầu so sánh các thuật toán học máy...")
            data_path = "/home/kieungan/DDoS_Detection_SDN/data/processed/live_traffic.csv"
            if not os.path.exists(data_path):
                logger.error(f"Không tìm thấy file dữ liệu: {data_path}")
                return

            df = pd.read_csv(data_path)
            if len(df) == 0:
                logger.error("File dữ liệu rỗng.")
                return

            sample_size = min(50000, len(df))
            df = df.sample(n=sample_size, random_state=42, replace=False)
            logger.info(f"Đã lấy mẫu {sample_size} dòng từ {len(df)} dòng dữ liệu.")

            if 'label' not in df.columns:
                logger.error("Dữ liệu không có cột 'label'. Vui lòng gắn nhãn dữ liệu trước.")
                return

            if df['label'].isnull().any():
                logger.info(f"Phát hiện giá trị NaN trong cột 'label'. Loại bỏ các dòng chứa NaN...")
                df = df.dropna(subset=['label'])
                if df.empty:
                    logger.error("Dữ liệu rỗng sau khi loại bỏ các dòng chứa NaN.")
                    return

            if df[['src_ip', 'dst_ip', 'protocol', 'length', 'src_port', 'dst_port']].isnull().any().any():
                logger.info("Phát hiện giá trị NaN trong các cột đặc trưng. Điền giá trị NaN bằng 0...")
                df[['src_ip', 'dst_ip', 'protocol', 'length', 'src_port', 'dst_port']] = df[['src_ip', 'dst_ip', 'protocol', 'length', 'src_port', 'dst_port']].fillna(0)

            df['src_ip'] = df['src_ip'].apply(lambda x: int(''.join([f'{int(i):03d}' for i in x.split('.')])) if pd.notna(x) else 0)
            df['dst_ip'] = df['dst_ip'].apply(lambda x: int(''.join([f'{int(i):03d}' for i in x.split('.')])) if pd.notna(x) else 0)
            logger.info("Đã chuyển đổi src_ip và dst_ip thành số nguyên.")

            logger.info(f"Số lượng mẫu dữ liệu: {len(df)}")
            label_counts = df['label'].value_counts()
            logger.info(f"Phân bố nhãn: \n{label_counts.to_string()}")

            X = df[['src_ip', 'dst_ip', 'protocol', 'length', 'src_port', 'dst_port']]
            y = df['label']

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            logger.info(f"Kích thước tập huấn luyện: {len(X_train)}")
            logger.info(f"Kích thước tập kiểm tra: {len(X_test)}")

            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

            with open(os.path.join(models_dir, "scaler.pkl"), "wb") as f:
                pickle.dump(scaler, f)
            logger.info("Đã lưu scaler mới.")

            class_weights = compute_class_weight('balanced', classes=[0, 1], y=y_train)
            logger.info(f"Trọng số lớp: {dict(zip([0, 1], class_weights))}")

            models = {
                'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, class_weight={0: class_weights[0], 1: class_weights[1]}),
                'SVM': LinearSVC(random_state=42, max_iter=1000, dual=True),
                'MLP': MLPClassifier(hidden_layer_sizes=(100,), max_iter=200, random_state=42)
            }

            results = []
            k_folds = 5
            for name, model in models.items():
                logger.info(f"Bắt đầu đánh giá mô hình {name}...")
                start_cv = time.time()
                cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=k_folds, scoring='accuracy')
                cv_time = time.time() - start_cv
                cv_accuracy = cv_scores.mean()

                start_train = time.time()
                model.fit(X_train_scaled, y_train)
                train_time = time.time() - start_train

                start_predict = time.time()
                y_pred = model.predict(X_test_scaled)
                predict_time = time.time() - start_predict

                test_accuracy = accuracy_score(y_test, y_pred)
                precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')

                results.append({
                    'Model': name,
                    'Cross-Validation Accuracy (mean)': cv_accuracy,
                    'Test Accuracy': test_accuracy,
                    'Precision': precision,
                    'Recall': recall,
                    'F1-Score': f1,
                    'Cross-Validation Time (s)': cv_time,
                    'Training Time (s)': train_time,
                    'Prediction Time (s)': predict_time
                })

                logger.info(f"Hoàn thành đánh giá mô hình {name}.")

            if isinstance(model, RandomForestClassifier):
                with open(os.path.join(models_dir, "rf_model.pkl"), "wb") as f:
                    pickle.dump(model, f)
                logger.info("Đã lưu mô hình Random Forest.")

            with open(comparison_report_path, 'w') as f:
                f.write("BÁO CÁO SO SÁNH HIỆU QUẢ CÁC THUẬT TOÁN PHÁT HIỆN DDoS\n")
                f.write("="*50 + "\n")
                f.write(f"Thời gian: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"Số lượng mẫu dữ liệu: {len(df)}\n")
                f.write(f"Số fold cross-validation: {k_folds}\n")
                f.write(f"Kích thước tập huấn luyện: {len(X_train)}\n")
                f.write(f"Kích thước tập kiểm tra: {len(X_test)}\n\n")
                f.write("Kết quả đánh giá:\n")
                f.write("-"*30 + "\n")

                for result in results:
                    f.write(f"Mô hình: {result['Model']}\n")
                    f.write(f"Độ chính xác Cross-Validation (trung bình): {result['Cross-Validation Accuracy (mean)']:.4f}\n")
                    f.write(f"Độ chính xác trên tập kiểm tra: {result['Test Accuracy']:.4f}\n")
                    f.write(f"Precision: {result['Precision']:.4f}\n")
                    f.write(f"Recall: {result['Recall']:.4f}\n")
                    f.write(f"F1-Score: {result['F1-Score']:.4f}\n")
                    f.write(f"Thời gian Cross-Validation: {result['Cross-Validation Time (s)']:.4f} giây\n")
                    f.write(f"Thời gian huấn luyện: {result['Training Time (s)']:.4f} giây\n")
                    f.write(f"Thời gian dự đoán: {result['Prediction Time (s)']:.4f} giây\n")
                    f.write("-"*30 + "\n")

            logger.info(f"Kết quả so sánh đã được lưu vào {comparison_report_path}")

        except Exception as e:
            logger.error(f"Lỗi khi so sánh các mô hình: {e}")
            return

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Flow mặc định
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Flow cho ARP
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1000, match, actions)

        # Flow cho whitelist IPv4
        for ip in self.whitelist_ips:
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_src=ip, ipv4_dst=self.server_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 800, match, actions)

            match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip, ipv4_dst=self.server_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 800, match, actions)

            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_src=ip, ipv4_dst=self.server_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 800, match, actions)

        # Flow cho lưu lượng IPv4 đến server
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=self.server_ip)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 600, match, actions)

        logger.info(f"Switch {datapath.id} đã kết nối.")

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

    def block_ip(self, datapath, ip_addr):
        if ip_addr in self.whitelist_ips:
            logger.info(f"IP {ip_addr} nằm trong whitelist, không chặn.")
            return

        if ip_addr in self.blocked_ips and (time.time() - self.blocked_ips[ip_addr]) < (self.block_duration + self.grace_period):
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_addr)
        actions = []
        self.add_flow(datapath, 900, match, actions, idle_timeout=self.block_duration)
        self.blocked_ips[ip_addr] = time.time()
        log_message = f"Đã chặn IP: {ip_addr} trong {self.block_duration} giây"
        logger.info(log_message)
        print(f"INFO - {log_message}")

    def unblock_expired_ips(self):
        current_time = time.time()
        expired_ips = [ip for ip, timestamp in self.blocked_ips.items()
                       if current_time - timestamp > self.block_duration]
        for ip in expired_ips:
            self.blocked_ips.pop(ip)
            log_message = f"Đã bỏ chặn IP: {ip}"
            logger.info(log_message)
            print(f"INFO - {log_message}")

    def reset_packet_counts(self):
        current_time = time.time()
        if current_time - self.last_reset >= self.window_duration:
            self.packet_counts.clear()
            self.last_reset = current_time

    def send_attack_response(self, datapath, ip_src, traffic_type):
        """Gửi thông báo khi phát hiện tấn công"""
        log_message = f"RESPONSE: Phát hiện {traffic_type} từ IP: {ip_src}. Chuẩn bị chặn."
        logger.info(log_message)
        print(f"INFO - {log_message}")

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
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, ofproto, parser, msg)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            return

        is_blocked = ip.src in self.blocked_ips
        if is_blocked:
            return

        self.reset_packet_counts()
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        traffic_type = "Không xác định"
        is_normal = ip.src in self.whitelist_ips

        if is_normal:
            if icmp_pkt:
                traffic_type = "ICMP"
            elif tcp_pkt:
                if tcp_pkt.dst_port == 80:
                    traffic_type = "HTTP"
                elif tcp_pkt.dst_port == 5001:
                    traffic_type = "TCP (iperf)"
                else:
                    traffic_type = "TCP"
            elif udp_pkt:
                if udp_pkt.dst_port == 5001:
                    traffic_type = "UDP (iperf)"
                else:
                    traffic_type = "UDP"
            log_message = f"Phát hiện lưu lượng bình thường {traffic_type} từ IP: {ip.src}"
            logger.info(log_message)
            print(f"INFO - {log_message}")
            print(log_message)
        else:
            block_ip = False
            if tcp_pkt and tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
                traffic_type = "SYN flood"
                self.packet_counts[ip.src]['syn'] += 1
                log_message = f"Phát hiện {traffic_type} từ IP: {ip.src}"
                logger.info(log_message)
                print(f"INFO - {log_message}")
                block_ip = True  # Chặn ngay khi phát hiện
            elif udp_pkt:
                traffic_type = "UDP flood"
                self.packet_counts[ip.src]['udp'] += 1
                log_message = f"Phát hiện {traffic_type} từ IP: {ip.src}"
                logger.info(log_message)
                print(f"INFO - {log_message}")
                block_ip = True  # Chặn ngay khi phát hiện
            elif icmp_pkt:
                traffic_type = "ICMP flood"
                self.packet_counts[ip.src]['icmp'] += 1
                log_message = f"Phát hiện {traffic_type} từ IP: {ip.src}"
                logger.info(log_message)
                print(f"INFO - {log_message}")
                block_ip = True  # Chặn ngay khi phát hiện
            else:
                traffic_type = "Mixed"
                log_message = f"Phát hiện {traffic_type} từ IP: {ip.src}"
                logger.info(log_message)
                print(f"INFO - {log_message}")
                block_ip = True  # Chặn ngay khi phát hiện

            if block_ip:
                self.send_attack_response(datapath, ip.src, traffic_type)
                self.block_ip(datapath, ip.src)
                return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip.src, ipv4_dst=ip.dst)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 700, match, actions)
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, in_port, eth, ofproto, parser, msg):
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
