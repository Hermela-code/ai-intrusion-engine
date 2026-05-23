
import sys
import time
import sqlite3
from collections import deque
import joblib
import numpy as np
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
from scapy.all import sniff, IP, TCP, UDP

try:
    model = joblib.load('idps_real_model.pkl')
    print("[*] AI Detection Brain loaded safely into memory pipeline.")
except FileNotFoundError:
    print("[-] Error: idps_real_model.pkl not found!")
    sys.exit(1)

packet_window = deque()
total_processed = 0
normal_processed = 0
attacks_processed = 0

def log_alert_to_db(src_ip, dst_ip, threat_type, risk, count):
    try:
        conn = sqlite3.connect('idps.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (source_ip, dest_ip, threat_type, risk_level, packet_count)
            VALUES (?, ?, ?, ?, ?)
        ''', (src_ip, dst_ip, threat_type, risk, count))
        conn.commit()
        conn.close()
        print(f"🚨 [ALERT LOGGED] {threat_type} from {src_ip} -> {dst_ip}")
    except Exception as e:
        print(f"[-] DB Error: {e}")

def simulate_prevention(src_ip):
    with open("IPs.txt", "a") as f:
        f.write(f"{src_ip}\n")
    print(f"🛡  [IPS MODULE] Dropped connection and blacklisted source IP: {src_ip}")

def process_packet(packet):
    global total_processed, normal_processed, attacks_processed
    if not packet.haslayer(IP):
        return
        
    total_processed += 1
    current_time = time.time()
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_len = len(packet)
    
    dst_port = 0
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        
    packet_window.append((current_time, dst_ip, dst_port))
    
    while packet_window and packet_window[0][0] < current_time - 2.0:
        packet_window.popleft()
        
    duration = 0.0
    src_bytes = packet_len
    dst_bytes = 0 
    
    count = sum(1 for item in packet_window if item[1] == dst_ip)
    srv_count = sum(1 for item in packet_window if item[2] == dst_port)
    
    features = np.array([[duration, src_bytes, dst_bytes, count, srv_count, count, srv_count]])
    prediction = model.predict(features)[0]
    
    if prediction != 0:
        attacks_processed += 1
        threat_name = "Port Scan/Probe" if prediction == 1 else "Denial of Service (DoS)"
        risk_level = "Medium" if prediction == 1 else "High"
        log_alert_to_db(src_ip, dst_ip, threat_name, risk_level, count)
        simulate_prevention(src_ip)
    else:
        normal_processed += 1
        
    if total_processed % 10 == 0:
        try:
            conn = sqlite3.connect('idps.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO stats (total_packets, normal_count, attack_count) VALUES (?, ?, ?)',
                           (total_processed, normal_processed, attacks_processed))
            conn.commit()
            conn.close()
            print(f"📊 [MONITOR] Processed {total_processed} packets (Normal: {normal_processed}, Threats: {attacks_processed})")
        except:
            pass

print("[*] Activating live interface sniffing loop... Press Ctrl+C to terminate.")
sniff(prn=process_packet, store=False)
