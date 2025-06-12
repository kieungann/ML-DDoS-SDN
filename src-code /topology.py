from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
import time
import threading
import os

# Đảm bảo thư mục logs tồn tại
log_dir = "/home/kieungan/DDoS_Detection_SDN/logs/"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

class CombinedTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Host bình thường
        h1 = self.addHost('h1', ip='10.0.0.1/8')
        h2 = self.addHost('h2', ip='10.0.0.2/8')
        h3 = self.addHost('h3', ip='10.0.0.3/8')
        h4 = self.addHost('h4', ip='10.0.0.4/8')
        h5 = self.addHost('h5', ip='10.0.0.5/8')

        # Host tấn công
        a1 = self.addHost('a1', ip='10.0.0.6/8')  # SYN flood
        a2 = self.addHost('a2', ip='10.0.0.9/8')  # UDP flood
        a3 = self.addHost('a3', ip='10.0.0.10/8') # ICMP flood
        a4 = self.addHost('a4', ip='10.0.0.7/8')  # SYN flood
        a5 = self.addHost('a5', ip='10.0.0.8/8')  # Mixed

        server = self.addHost('server', ip='10.0.0.11/8')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s3)
        self.addLink(h5, s3)

        self.addLink(a1, s1)
        self.addLink(a2, s2)
        self.addLink(a3, s3)
        self.addLink(a4, s1)
        self.addLink(a5, s1)

        self.addLink(server, s3)

        self.addLink(s1, s2)
        self.addLink(s2, s3)

def run_traffic(host, target_ip, duration=1800):  # Giảm lưu lượng bình thường
    print(f"{host.name} đang tạo lưu lượng bình thường đến server ({target_ip})...")
    host.cmd(f'ping -c 10000 {target_ip} >> {log_dir}{host.name}_ping.log 2>&1 &')
    host.cmd(f'iperf -c {target_ip} -p 5001 -t {duration} -b 10M >> {log_dir}{host.name}_iperf_tcp.log 2>&1 &')
    host.cmd(f'iperf -u -c {target_ip} -p 5001 -t {duration} -b 10M >> {log_dir}{host.name}_iperf_udp.log 2>&1 &')
    host.cmd(f'hping3 -2 -c 10000 {target_ip} >> {log_dir}{host.name}_hping3_udp.log 2>&1 &')
    host.cmd(f'while true; do curl -s http://{target_ip}:80 -o /dev/null >> {log_dir}{host.name}_curl.log 2>&1; sleep 0.5; done &')
    time.sleep(duration)
    host.cmd('killall ping iperf hping3 curl')

def run_attack(host, target_ip, attack_type, duration=3600):  # Tăng lưu lượng tấn công
    print(f"{host.name} đang thực hiện {attack_type} tấn công server ({target_ip})...")
    log_file = f"{log_dir}{host.name}_{attack_type.replace(' ', '_').lower()}.log"
    if attack_type == "SYN flood":
        result = host.cmd(f'hping3 -S -p 80 --flood -d 20 --rand-source --count 10000 {target_ip} >> {log_file} 2>&1 & sleep {duration}; killall hping3')
    elif attack_type == "UDP flood":
        result = host.cmd(f'hping3 -2 --flood -d 20 --rand-source --count 10000 {target_ip} >> {log_file} 2>&1 & sleep {duration}; killall hping3')
    elif attack_type == "ICMP flood":
        result = host.cmd(f'hping3 -1 --flood --rand-source --count 10000 {target_ip} >> {log_file} 2>&1 & sleep {duration}; killall hping3')
    elif attack_type == "Mixed":
        result = host.cmd(f'hping3 -S -p 80 --flood -d 20 --rand-source --count 5000 {target_ip} >> {log_file} 2>&1 & hping3 -2 --flood -d 20 --rand-source --count 5000 {target_ip} >> {log_file} 2>&1 & sleep {duration}; killall hping3')
    print(f"Kết quả tấn công từ {host.name}: {result}")

def run():
    topo = CombinedTopo()
    net = Mininet(topo=topo, controller=RemoteController('c0', ip='127.0.0.1', port=6653), switch=OVSSwitch, link=TCLink)
    net.start()

    for switch in ['s1', 's2', 's3']:
        net[switch].cmd('ovs-vsctl set bridge {} protocols=OpenFlow13'.format(switch))

    server = net.get('server')
    server.cmd('killall iperf')
    server.cmd('iperf -s -p 5001 >> /home/kieungan/DDoS_Detection_SDN/logs/server_iperf.log 2>&1 &')
    server.cmd('python3 -m http.server 80 >> /home/kieungan/DDoS_Detection_SDN/logs/server_http.log 2>&1 &')

    print("Đợi controller thiết lập flow...")
    time.sleep(20)

    print("Giới hạn tài nguyên trên server...")
    server.cmd('stress --cpu 2 --vm 1 --vm-bytes 128M --timeout 120 &')

    print("Kiểm tra kết nối từ các host bình thường đến Server...")
    for host_name in ['h1', 'h2', 'h3', 'h4', 'h5']:
        host = net.get(host_name)
        result = host.cmd('ping -c 4 10.0.0.11')
        print(f"Kết nối từ {host_name}: {result}")

    print("Bắt đầu tạo lưu lượng bình thường và tấn công DDoS...")
    normal_hosts = ['h1', 'h2', 'h3', 'h4', 'h5']
    normal_threads = []
    for host_name in normal_hosts:
        host = net.get(host_name)
        thread = threading.Thread(target=run_traffic, args=(host, '10.0.0.11', 1800))
        normal_threads.append(thread)
        thread.start()

    attackers = [
        ('a1', 'SYN flood'),
        ('a2', 'UDP flood'),
        ('a3', 'ICMP flood'),
        ('a4', 'SYN flood'),
        ('a5', 'Mixed')
    ]
    attack_threads = []
    for attacker_name, attack_type in attackers:
        host = net.get(attacker_name)
        thread = threading.Thread(target=run_attack, args=(host, '10.0.0.11', attack_type, 3600))
        attack_threads.append(thread)
        thread.start()

    for thread in normal_threads:
        thread.join()
    for thread in attack_threads:
        thread.join()

    time.sleep(20)

    print("Kiểm tra lại kết nối từ các host bình thường đến Server...")
    for host_name in ['h1', 'h2', 'h3', 'h4', 'h5']:
        host = net.get(host_name)
        result = host.cmd('ping -c 4 10.0.0.11')
        print(f"Kết nối từ {host_name}: {result}")

    # Mở giao diện CLI và giữ mạng cho đến khi người dùng thoát
    CLI(net)
    
    # Chỉ dừng mạng khi người dùng thoát CLI
    print("Dừng mạng Mininet...")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
