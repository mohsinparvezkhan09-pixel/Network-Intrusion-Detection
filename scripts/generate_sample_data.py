"""
Sample Network Traffic Generator for Network Intrusion Detection System.
Generates realistic network flow records matching standard CIC-IDS2017 features.
"""

import os
import numpy as np
import pandas as pd

def generate_network_traffic(num_records: int = 4000, random_state: int = 42) -> pd.DataFrame:
    np.random.seed(random_state)
    
    # Class distribution:
    # 60% Benign, 12% DoS, 10% DDoS, 8% PortScan, 6% BruteForce, 4% Botnet
    classes = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Botnet"]
    weights = [0.60, 0.12, 0.10, 0.08, 0.06, 0.04]
    
    labels = np.random.choice(classes, size=num_records, p=weights)
    
    rows = []
    for label in labels:
        if label == "BENIGN":
            port = np.random.choice([80, 443, 53, 8080, 25, 110, 8443], p=[0.3, 0.45, 0.1, 0.05, 0.04, 0.03, 0.03])
            flow_duration = int(np.random.exponential(scale=500000) + 1000)
            tot_fwd_pkts = int(np.random.poisson(lam=12) + 2)
            tot_bwd_pkts = int(np.random.poisson(lam=15) + 2)
            fwd_pkt_len_mean = float(np.clip(np.random.normal(loc=350, scale=80), 40, 1460))
            bwd_pkt_len_mean = float(np.clip(np.random.normal(loc=850, scale=200), 40, 1460))
            fwd_pkt_len_max = float(min(1500, fwd_pkt_len_mean * np.random.uniform(1.2, 2.5)))
            fwd_pkt_len_min = float(max(20, fwd_pkt_len_mean * np.random.uniform(0.1, 0.5)))
            bwd_pkt_len_max = float(min(1500, bwd_pkt_len_mean * np.random.uniform(1.2, 2.0)))
            bwd_pkt_len_min = float(max(20, bwd_pkt_len_mean * np.random.uniform(0.1, 0.5)))
            tot_len_fwd = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd = tot_bwd_pkts * bwd_pkt_len_mean
            flow_bytes_s = (tot_len_fwd + tot_len_bwd) / max(flow_duration / 1e6, 0.001)
            flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / max(flow_duration / 1e6, 0.001)
            flow_iat_mean = flow_duration / max((tot_fwd_pkts + tot_bwd_pkts - 1), 1)
            flow_iat_std = flow_iat_mean * np.random.uniform(0.2, 0.8)
            flow_iat_max = flow_iat_mean * np.random.uniform(1.5, 3.0)
            flow_iat_min = max(0, flow_iat_mean * np.random.uniform(0.01, 0.2))
            fwd_iat_mean = flow_duration / max(tot_fwd_pkts, 1)
            bwd_iat_mean = flow_duration / max(tot_bwd_pkts, 1)
            fwd_psh_flags = 1 if np.random.rand() < 0.25 else 0
            syn_flag_count = 1 if np.random.rand() < 0.15 else 0
            rst_flag_count = 0
            ack_flag_count = 1 if np.random.rand() < 0.85 else 0
            urg_flag_count = 0
            down_up_ratio = round(tot_bwd_pkts / max(tot_fwd_pkts, 1), 2)
            avg_pkt_size = (tot_len_fwd + tot_len_bwd) / max((tot_fwd_pkts + tot_bwd_pkts), 1)
            init_win_fwd = int(np.random.choice([29200, 65535, 8192, 14600]))
            init_win_bwd = int(np.random.choice([29200, 65535, 8192, 14600]))
            act_data_pkt_fwd = max(1, int(tot_fwd_pkts * 0.7))
            min_seg_size_fwd = 20 or 32

        elif label == "DoS":
            port = int(np.random.choice([80, 443, 8080]))
            flow_duration = int(np.random.uniform(5000000, 30000000))  # Long slowloris or flood
            tot_fwd_pkts = int(np.random.uniform(150, 800))
            tot_bwd_pkts = int(np.random.uniform(1, 10))  # Few or no responses
            fwd_pkt_len_mean = float(np.random.uniform(50, 150))
            bwd_pkt_len_mean = float(np.random.uniform(0, 60))
            fwd_pkt_len_max = float(min(500, fwd_pkt_len_mean * 2.0))
            fwd_pkt_len_min = 40.0
            bwd_pkt_len_max = 60.0
            bwd_pkt_len_min = 0.0
            tot_len_fwd = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd = tot_bwd_pkts * bwd_pkt_len_mean
            flow_bytes_s = (tot_len_fwd + tot_len_bwd) / max(flow_duration / 1e6, 0.001)
            flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / max(flow_duration / 1e6, 0.001)
            flow_iat_mean = flow_duration / max((tot_fwd_pkts + tot_bwd_pkts), 1)
            flow_iat_std = flow_iat_mean * np.random.uniform(0.1, 0.4)
            flow_iat_max = flow_iat_mean * np.random.uniform(1.2, 2.0)
            flow_iat_min = max(0, flow_iat_mean * 0.1)
            fwd_iat_mean = flow_duration / max(tot_fwd_pkts, 1)
            bwd_iat_mean = 0.0 if tot_bwd_pkts == 0 else flow_duration / tot_bwd_pkts
            fwd_psh_flags = 1 if np.random.rand() < 0.6 else 0
            syn_flag_count = 1 if np.random.rand() < 0.4 else 0
            rst_flag_count = 1 if np.random.rand() < 0.3 else 0
            ack_flag_count = 1 if np.random.rand() < 0.5 else 0
            urg_flag_count = 0
            down_up_ratio = round(tot_bwd_pkts / max(tot_fwd_pkts, 1), 2)
            avg_pkt_size = (tot_len_fwd + tot_len_bwd) / max((tot_fwd_pkts + tot_bwd_pkts), 1)
            init_win_fwd = int(np.random.choice([256, 512, 1024, 0]))
            init_win_bwd = int(np.random.choice([0, 256, -1]))
            act_data_pkt_fwd = int(tot_fwd_pkts * 0.9)
            min_seg_size_fwd = 32

        elif label == "DDoS":
            port = int(np.random.choice([80, 443, 53, 123]))
            flow_duration = int(np.random.uniform(10000, 800000))
            tot_fwd_pkts = int(np.random.uniform(300, 2000))
            tot_bwd_pkts = int(np.random.choice([0, 1, 2]))
            fwd_pkt_len_mean = float(np.random.uniform(40, 100))
            bwd_pkt_len_mean = 0.0 if tot_bwd_pkts == 0 else float(np.random.uniform(40, 60))
            fwd_pkt_len_max = float(max(64, fwd_pkt_len_mean * 1.5))
            fwd_pkt_len_min = 40.0
            bwd_pkt_len_max = bwd_pkt_len_mean
            bwd_pkt_len_min = 0.0
            tot_len_fwd = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd = tot_bwd_pkts * bwd_pkt_len_mean
            flow_bytes_s = (tot_len_fwd + tot_len_bwd) / max(flow_duration / 1e6, 0.001)
            flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / max(flow_duration / 1e6, 0.001)
            flow_iat_mean = flow_duration / max((tot_fwd_pkts + tot_bwd_pkts), 1)
            flow_iat_std = flow_iat_mean * np.random.uniform(0.05, 0.2)
            flow_iat_max = flow_iat_mean * 1.5
            flow_iat_min = max(0, flow_iat_mean * 0.01)
            fwd_iat_mean = flow_iat_mean
            bwd_iat_mean = 0.0
            fwd_psh_flags = 0
            syn_flag_count = 1
            rst_flag_count = 1 if np.random.rand() < 0.5 else 0
            ack_flag_count = 0
            urg_flag_count = 0
            down_up_ratio = 0.0
            avg_pkt_size = fwd_pkt_len_mean
            init_win_fwd = int(np.random.choice([1024, 2048, 4096]))
            init_win_bwd = -1
            act_data_pkt_fwd = 0
            min_seg_size_fwd = 20

        elif label == "PortScan":
            port = int(np.random.randint(1, 65535))
            flow_duration = int(np.random.uniform(100, 50000))
            tot_fwd_pkts = int(np.random.choice([1, 2, 3]))
            tot_bwd_pkts = int(np.random.choice([0, 1]))
            fwd_pkt_len_mean = float(np.random.choice([0, 40, 44, 60]))
            bwd_pkt_len_mean = float(np.random.choice([0, 40]))
            fwd_pkt_len_max = fwd_pkt_len_mean
            fwd_pkt_len_min = fwd_pkt_len_mean
            bwd_pkt_len_max = bwd_pkt_len_mean
            bwd_pkt_len_min = bwd_pkt_len_mean
            tot_len_fwd = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd = tot_bwd_pkts * bwd_pkt_len_mean
            flow_bytes_s = (tot_len_fwd + tot_len_bwd) / max(flow_duration / 1e6, 0.001)
            flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / max(flow_duration / 1e6, 0.001)
            flow_iat_mean = float(flow_duration / max((tot_fwd_pkts + tot_bwd_pkts), 1))
            flow_iat_std = 0.0
            flow_iat_max = flow_iat_mean
            flow_iat_min = flow_iat_mean
            fwd_iat_mean = flow_iat_mean
            bwd_iat_mean = 0.0
            fwd_psh_flags = 0
            syn_flag_count = 1
            rst_flag_count = 1 if tot_bwd_pkts > 0 else 0
            ack_flag_count = 0
            urg_flag_count = 0
            down_up_ratio = 0.0 if tot_fwd_pkts == 0 else round(tot_bwd_pkts / tot_fwd_pkts, 2)
            avg_pkt_size = fwd_pkt_len_mean
            init_win_fwd = int(np.random.choice([1024, 2048, 8192]))
            init_win_bwd = int(np.random.choice([-1, 0, 512]))
            act_data_pkt_fwd = 0
            min_seg_size_fwd = 20 or 32

        elif label == "BruteForce":
            port = int(np.random.choice([21, 22, 3389, 445]))  # FTP, SSH, RDP, SMB
            flow_duration = int(np.random.uniform(200000, 1500000))
            tot_fwd_pkts = int(np.random.poisson(lam=22) + 5)
            tot_bwd_pkts = int(np.random.poisson(lam=18) + 4)
            fwd_pkt_len_mean = float(np.clip(np.random.normal(loc=95, scale=25), 40, 300))
            bwd_pkt_len_mean = float(np.clip(np.random.normal(loc=120, scale=30), 40, 400))
            fwd_pkt_len_max = float(fwd_pkt_len_mean * 2.2)
            fwd_pkt_len_min = 40.0
            bwd_pkt_len_max = float(bwd_pkt_len_mean * 2.0)
            bwd_pkt_len_min = 40.0
            tot_len_fwd = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd = tot_bwd_pkts * bwd_pkt_len_mean
            flow_bytes_s = (tot_len_fwd + tot_len_bwd) / max(flow_duration / 1e6, 0.001)
            flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / max(flow_duration / 1e6, 0.001)
            flow_iat_mean = flow_duration / max((tot_fwd_pkts + tot_bwd_pkts - 1), 1)
            flow_iat_std = flow_iat_mean * np.random.uniform(0.1, 0.3)
            flow_iat_max = flow_iat_mean * 2.0
            flow_iat_min = max(0, flow_iat_mean * 0.1)
            fwd_iat_mean = flow_duration / max(tot_fwd_pkts, 1)
            bwd_iat_mean = flow_duration / max(tot_bwd_pkts, 1)
            fwd_psh_flags = 1
            syn_flag_count = 1 if np.random.rand() < 0.2 else 0
            rst_flag_count = 1 if np.random.rand() < 0.6 else 0
            ack_flag_count = 1
            urg_flag_count = 0
            down_up_ratio = round(tot_bwd_pkts / max(tot_fwd_pkts, 1), 2)
            avg_pkt_size = (tot_len_fwd + tot_len_bwd) / max((tot_fwd_pkts + tot_bwd_pkts), 1)
            init_win_fwd = int(np.random.choice([14600, 29200]))
            init_win_bwd = int(np.random.choice([14600, 29200]))
            act_data_pkt_fwd = int(tot_fwd_pkts * 0.8)
            min_seg_size_fwd = 32

        else:  # Botnet
            port = int(np.random.choice([6667, 8080, 53, 443, 8000, 1080]))
            flow_duration = int(np.random.uniform(1000000, 60000000))  # Periodic beaconing
            tot_fwd_pkts = int(np.random.uniform(8, 30))
            tot_bwd_pkts = int(np.random.uniform(6, 25))
            fwd_pkt_len_mean = float(np.random.uniform(60, 180))
            bwd_pkt_len_mean = float(np.random.uniform(80, 220))
            fwd_pkt_len_max = float(fwd_pkt_len_mean * 1.8)
            fwd_pkt_len_min = 40.0
            bwd_pkt_len_max = float(bwd_pkt_len_mean * 1.8)
            bwd_pkt_len_min = 40.0
            tot_len_fwd = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd = tot_bwd_pkts * bwd_pkt_len_mean
            flow_bytes_s = (tot_len_fwd + tot_len_bwd) / max(flow_duration / 1e6, 0.001)
            flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / max(flow_duration / 1e6, 0.001)
            # Characteristic low std IAT (rigid heartbeat beacon)
            flow_iat_mean = flow_duration / max((tot_fwd_pkts + tot_bwd_pkts), 1)
            flow_iat_std = flow_iat_mean * np.random.uniform(0.01, 0.08)  # very regular
            flow_iat_max = flow_iat_mean * 1.15
            flow_iat_min = flow_iat_mean * 0.85
            fwd_iat_mean = flow_duration / max(tot_fwd_pkts, 1)
            bwd_iat_mean = flow_duration / max(tot_bwd_pkts, 1)
            fwd_psh_flags = 1 if np.random.rand() < 0.4 else 0
            syn_flag_count = 0
            rst_flag_count = 0
            ack_flag_count = 1
            urg_flag_count = 0
            down_up_ratio = round(tot_bwd_pkts / max(tot_fwd_pkts, 1), 2)
            avg_pkt_size = (tot_len_fwd + tot_len_bwd) / max((tot_fwd_pkts + tot_bwd_pkts), 1)
            init_win_fwd = int(np.random.choice([65535, 8192]))
            init_win_bwd = int(np.random.choice([65535, 8192]))
            act_data_pkt_fwd = int(tot_fwd_pkts * 0.7)
            min_seg_size_fwd = 32

        rows.append({
            "Destination Port": port,
            "Flow Duration": flow_duration,
            "Total Fwd Packets": tot_fwd_pkts,
            "Total Backward Packets": tot_bwd_pkts,
            "Total Length of Fwd Packets": round(tot_len_fwd, 2),
            "Total Length of Bwd Packets": round(tot_len_bwd, 2),
            "Fwd Packet Length Max": round(fwd_pkt_len_max, 2),
            "Fwd Packet Length Min": round(fwd_pkt_len_min, 2),
            "Fwd Packet Length Mean": round(fwd_pkt_len_mean, 2),
            "Bwd Packet Length Max": round(bwd_pkt_len_max, 2),
            "Bwd Packet Length Min": round(bwd_pkt_len_min, 2),
            "Bwd Packet Length Mean": round(bwd_pkt_len_mean, 2),
            "Flow Bytes/s": round(flow_bytes_s, 2),
            "Flow Packets/s": round(flow_pkts_s, 2),
            "Flow IAT Mean": round(flow_iat_mean, 2),
            "Flow IAT Std": round(flow_iat_std, 2),
            "Flow IAT Max": round(flow_iat_max, 2),
            "Flow IAT Min": round(flow_iat_min, 2),
            "Fwd IAT Mean": round(fwd_iat_mean, 2),
            "Bwd IAT Mean": round(bwd_iat_mean, 2),
            "Fwd PSH Flags": int(fwd_psh_flags),
            "SYN Flag Count": int(syn_flag_count),
            "RST Flag Count": int(rst_flag_count),
            "ACK Flag Count": int(ack_flag_count),
            "URG Flag Count": int(urg_flag_count),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": round(avg_pkt_size, 2),
            "Init_Win_bytes_forward": int(init_win_fwd),
            "Init_Win_bytes_backward": int(init_win_bwd),
            "act_data_pkt_fwd": int(act_data_pkt_fwd),
            "min_seg_size_forward": int(min_seg_size_fwd),
            "Label": label
        })
        
    df = pd.DataFrame(rows)
    return df

if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "sample_traffic.csv")
    df = generate_network_traffic(num_records=4500, random_state=42)
    df.to_csv(out_file, index=False)
    print(f"Generated sample traffic dataset: {out_file} ({len(df)} records)")
    print("Class distribution:")
    print(df["Label"].value_counts())
