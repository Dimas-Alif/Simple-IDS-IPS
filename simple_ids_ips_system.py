import json
import os
import subprocess
import logging
import streamlit as st
from datetime import datetime
from scapy.all import sniff, send, IP, ICMP
from elasticsearch import Elasticsearch
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
import pandas as pd
import pyshark
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from cryptography.fernet import Fernet
from keras.models import Model
from keras.layers import Input, Dense
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from dotenv import load_dotenv
from kafka import KafkaProducer

# Load environment variables (like API key, database connection details)
load_dotenv()

# Konfigurasi Logging
LOG_FOLDER = "logs"
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

logging.basicConfig(
    filename=f"{LOG_FOLDER}/ids_logs.log", 
    level=logging.INFO, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Elasticsearch konfigurasi
es = Elasticsearch(os.getenv("ELASTICSEARCH_URL"))

# Kafka Producer untuk Pengelolaan Data Log
producer = KafkaProducer(
    bootstrap_servers=[os.getenv("KAFKA_SERVER")],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# Fungsi untuk Memulai Snort dalam Mode Logging
def start_snort():
    snort_command = (
        "snort -A console -q -c snort_rules/snort.conf "
        f"-l {LOG_FOLDER} -i eth0"
    )
    try:
        print("[INFO] Memulai Snort...")
        subprocess.Popen(snort_command, shell=True)
        print("[INFO] Snort berjalan.")
    except Exception as e:
        print(f"[ERROR] Gagal memulai Snort: {e}")

# Fungsi untuk Memproses Lalu Lintas Real-Time
def process_packet(packet):
    try:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            protocol = packet["IP"].proto

            # Deteksi DDoS
            ddos_detected = detect_ddos(src_ip)
            if ddos_detected:
                logging.warning(f"[ALERT] DDoS terdeteksi dari {src_ip} ke {dst_ip}")
                return  # Blokir paket dari IP tersebut

            # Deteksi serangan aplikasi web (SQL Injection, XSS)
            web_attack_detected = detect_web_attack(packet)
            if web_attack_detected:
                logging.warning(f"[ALERT] Serangan aplikasi web terdeteksi dari {src_ip}")
                return  # Blokir paket ini

            # Log aktivitas jaringan
            log_entry = {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": protocol,
                "timestamp": datetime.now().isoformat()
            }
            encrypted_log = encrypt_log(log_entry)  # Enkripsi log
            logging.info(f"Lalu lintas: {src_ip} -> {dst_ip} | Protokol: {protocol}")

            # Kirim log ke Elasticsearch
            es.index(index="ids_logs", document=encrypted_log)

            # Kirim log ke Kafka untuk pemrosesan lebih lanjut
            producer.send(os.getenv("KAFKA_TOPIC"), value=encrypted_log)

            # Deteksi anomali dengan model AI
            anomaly_data = pd.DataFrame([log_entry])
            model = joblib.load('ml_models/final_model.pkl')  # Menggunakan model yang sudah dilatih
            predictions = model.predict(anomaly_data)
            if predictions == -1:
                print(f"[ALERT] Anomali terdeteksi dari {src_ip} ke {dst_ip}")

            # Deteksi ancaman berdasarkan Threat Intelligence
            threat_intelligence(src_ip)

            # Analisis Trafik SSL/TLS
            analyze_ssl_traffic(packet)

            # Honeytoken: deteksi IP yang mengakses honeytoken
            honeytoken_trigger(packet)

    except Exception as e:
        print(f"[ERROR] Gagal memproses paket: {e}")

# Fungsi untuk mendeteksi DDoS
def detect_ddos(src_ip):
    ddos_threshold = 100
    count = es.count(index="ids_logs", body={"query": {"term": {"source_ip": src_ip}}})['count']
    if count > ddos_threshold:
        return True
    return False

# Fungsi untuk mendeteksi serangan aplikasi web (SQL Injection, XSS)
def detect_web_attack(packet):
    if packet.haslayer("HTTP"):
        if "SELECT" in str(packet["HTTP"].payload) or "UNION" in str(packet["HTTP"].payload):
            return True
        elif "<script>" in str(packet["HTTP"].payload):
            return True
    return False

# Fungsi untuk mengenkripsi log menggunakan AES
def encrypt_log(log_entry):
    key = generate_secure_key()  # Gunakan kunci yang aman untuk enkripsi
    fernet = Fernet(key)
    log_json = json.dumps(log_entry).encode()
    encrypted_log = fernet.encrypt(log_json)
    return encrypted_log

# Fungsi untuk menghasilkan kunci yang aman menggunakan PBKDF2
def generate_secure_key():
    password = os.getenv("ENCRYPTION_PASSWORD").encode()
    salt = os.urandom(16)  # Salt yang lebih aman
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Fungsi Integrasi dengan Threat Intelligence
def threat_intelligence(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        'Key': os.getenv("ABUSEIPDB_API_KEY"),
        'Accept': 'application/json'
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    if 'data' in data and data['data']['isWhitelisted'] is False:
        logging.warning(f"[ALERT] IP {ip} terdeteksi sebagai ancaman global.")
        es.index(index="blacklist", document={"source_ip": ip, "timestamp": datetime.now().isoformat()})

# Deep Packet Inspection (DPI)
def deep_packet_inspection(interface):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously(packet_count=10):
            try:
                if "HTTP" in packet:
                    print(f"HTTP Payload: {packet.http.file_data}")
                else:
                    print(f"Packet Info: {packet}")
            except AttributeError:
                continue
    except Exception as e:
        print(f"[ERROR] Gagal menganalisis paket: {e}")

# Fungsi untuk menganalisis trafik SSL/TLS
def analyze_ssl_traffic(packet):
    if "TLS" in packet:
        print(f"[INFO] Paket TLS terdeteksi: {packet.summary()}")

# Fungsi untuk mengaktifkan honeytoken (honeypot)
def honeytoken_trigger(packet):
    honeytoken_ip = "192.168.1.100"
    if packet.haslayer("IP") and packet["IP"].src == honeytoken_ip:
        logging.warning(f"[ALERT] Aktivitas mencurigakan dihoneypot dari {packet['IP'].src}")
        automatic_response(packet["IP"].src)

# Fungsi untuk memberikan respons otomatis
def automatic_response(ip):
    print(f"[INFO] Memutuskan koneksi IP: {ip}")
    # Kirim paket ICMP ke IP yang mencurigakan untuk memutuskan koneksi
    response_packet = IP(dst=ip)/ICMP(type=3, code=13)
    send(response_packet)
    logging.info(f"[ALERT] Koneksi IP {ip} diputus")

# Fungsi untuk Menampilkan Dashboard di Streamlit
def display_dashboard():
    st.title("IDS/IPS Dashboard")
    st.sidebar.title("Pengaturan")
    log_file = f"{LOG_FOLDER}/ids_logs.log"

    # Visualisasi log dan ancaman
    st.header("Laporan Ancaman")
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            logs = f.readlines()
            st.text_area("Log IDS", value="".join(logs), height=400)

    # Statistik Ancaman
    st.header("Statistik Ancaman")
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            logs = f.readlines()
            total_traffic = len(logs)
            alerts = [log for log in logs if "ALERT" in log]
            st.metric("Total Lalu Lintas", total_traffic)
            st.metric("Total Ancaman", len(alerts))

    # Statistik dari Elasticsearch
    st.header("Distribusi Ancaman")
    query = {"query": {"match_all": {}}}
    response = es.search(index="ids_logs", body=query)
    threats = [hit["_source"] for hit in response["hits"]["hits"]]
    threat_df = pd.DataFrame(threats)
    st.bar_chart(threat_df["protocol"].value_counts())

# Fungsi untuk Melatih Model AI dengan Dataset
def train_ai_model():
    dataset = pd.read_csv("datasets/realistic_attack_data.csv")
    X = dataset.drop("label", axis=1)
    y = dataset["label"]

    # Latih model menggunakan Random Forest
    model_rf = RandomForestClassifier(n_estimators=100)
    model_rf.fit(X, y)
    joblib.dump(model_rf, 'ml_models/final_model.pkl')

# Fungsi Utama
if __name__ == "__main__":
    print("=== Sistem IDS/IPS ===")
    print("1. Jalankan Snort")
    print("2. Tangkap Lalu Lintas Real-Time")
    print("3. Tampilkan Dashboard Streamlit")
    print("4. Analisis Paket Mendalam")
    print("5. Latih Model AI")
    choice = input("Pilih opsi: ")

    if choice == "1":
        start_snort()
    elif choice == "2":
        sniff(prn=process_packet, filter="ip", store=False)
    elif choice == "3":
        os.system("streamlit run ids_snort_integration.py")
    elif choice == "4":
        interface = input("Masukkan interface jaringan: ")
        deep_packet_inspection(interface)
    elif choice == "5":
        train_ai_model()
    else:
        print("[INFO] Pilihan tidak valid.")
