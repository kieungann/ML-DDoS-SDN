import pandas as pd
import numpy as np
from scapy.all import rdpcap
import os

# Hàm trích xuất đặc trưng từ file pcap
def extract_features(pcap_file, label):
    print(f"Đang trích xuất đặc trưng từ file: {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Lỗi khi đọc file {pcap_file}: {e}")
        return []
    
    features = []
    for pkt in packets:
        if 'IP' in pkt:
            feature = {
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst,
                'protocol': pkt['IP'].proto,
                'length': len(pkt),
                'src_port': pkt.sport if 'TCP' in pkt or 'UDP' in pkt else 0,
                'dst_port': pkt.dport if 'TCP' in pkt or 'UDP' in pkt else 0,
                'label': label  # 0: normal, 1: attack
            }
            features.append(feature)
    
    print(f"Đã trích xuất {len(features)} mẫu từ file {pcap_file}")
    return features

# Thư mục chứa dữ liệu
raw_dir = "/home/kieungan/DDoS_Detection_SDN/data/raw/"
processed_dir = "/home/kieungan/DDoS_Detection_SDN/data/processed/"

# Tạo thư mục processed nếu chưa tồn tại
if not os.path.exists(processed_dir):
    print(f"Tạo thư mục: {processed_dir}")
    os.makedirs(processed_dir)

# Xử lý các file
print("Đang liệt kê các file trong thư mục raw...")
normal_files = [f for f in os.listdir(raw_dir) if 'normal' in f]
ddos_files = [f for f in os.listdir(raw_dir) if 'ddos' in f]
print(f"Đã tìm thấy {len(normal_files)} file bình thường: {normal_files}")
print(f"Đã tìm thấy {len(ddos_files)} file tấn công: {ddos_files}")

all_features = []

# Xử lý lưu lượng bình thường
print("Bắt đầu xử lý lưu lượng bình thường...")
for file in normal_files:
    features = extract_features(os.path.join(raw_dir, file), 0)
    all_features.extend(features)

# Xử lý lưu lượng tấn công
print("Bắt đầu xử lý lưu lượng tấn công...")
for file in ddos_files:
    features = extract_features(os.path.join(raw_dir, file), 1)
    all_features.extend(features)

# Chuyển thành DataFrame và lưu
print(f"Tổng số mẫu trích xuất: {len(all_features)}")
df = pd.DataFrame(all_features)
print("Đang lưu dataset vào dataset.csv...")
df.to_csv(os.path.join(processed_dir, "dataset.csv"), index=False)
print("Đã lưu dataset.csv")

# Tiền xử lý: Chuẩn hóa và cân bằng dữ liệu
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE

# Đọc dataset
print("Đang đọc dataset.csv...")
df = pd.read_csv(os.path.join(processed_dir, "dataset.csv"))

# Chuyển đổi IP thành số
print("Đang chuyển đổi địa chỉ IP thành số...")
df['src_ip'] = df['src_ip'].apply(lambda x: int(''.join([f'{int(i):03d}' for i in x.split('.')])))
df['dst_ip'] = df['dst_ip'].apply(lambda x: int(''.join([f'{int(i):03d}' for i in x.split('.')])))

# Chuẩn hóa dữ liệu
print("Đang chuẩn hóa dữ liệu...")
scaler = StandardScaler()
numeric_cols = ['src_ip', 'dst_ip', 'protocol', 'length', 'src_port', 'dst_port']
df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

# Cân bằng dữ liệu bằng SMOTE
print("Đang cân bằng dữ liệu bằng SMOTE...")
X = df.drop('label', axis=1)
y = df['label']
smote = SMOTE(random_state=42)
X_balanced, y_balanced = smote.fit_resample(X, y)
print(f"Số mẫu sau khi cân bằng: {len(X_balanced)}")

# Lưu dataset đã xử lý
print("Đang lưu dataset đã cân bằng vào balanced_dataset.csv...")
balanced_df = pd.DataFrame(X_balanced, columns=X.columns)
balanced_df['label'] = y_balanced
balanced_df.to_csv(os.path.join(processed_dir, "balanced_dataset.csv"), index=False)
print("Đã lưu balanced_dataset.csv")

# Tạo thư mục models nếu chưa tồn tại
models_dir = "../../models/"
if not os.path.exists(models_dir):
    print(f"Tạo thư mục: {models_dir}")
    os.makedirs(models_dir)

# Lưu scaler để sử dụng sau
print("Đang lưu scaler vào scaler.pkl...")
import pickle
with open(os.path.join(models_dir, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)
print("Đã lưu scaler.pkl")
print("Hoàn thành tiền xử lý dữ liệu!")
