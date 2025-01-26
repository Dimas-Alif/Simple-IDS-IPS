# IDS/IPS (Intrusion Detection and Prevention System)

Sistem IDS/IPS ini dirancang untuk mendeteksi dan mencegah ancaman di jaringan dengan menggunakan kombinasi berbagai teknik, termasuk analisis paket jaringan, deteksi anomali berbasis AI, integrasi intelijen ancaman, dan enkripsi data log. Sistem ini juga dilengkapi dengan fungsionalitas honeypot dan pemrosesan log yang lebih canggih menggunakan Elasticsearch dan Kafka.

## Fitur

- **Snort IDS**: Menggunakan Snort untuk mendeteksi ancaman dan menyimpan log.
- **DDoS Detection**: Mendeteksi serangan DDoS berdasarkan jumlah permintaan dari IP sumber.
- **Web Attack Detection**: Mendeteksi potensi serangan aplikasi web seperti SQL Injection dan XSS.
- **AI Anomaly Detection**: Menggunakan model Random Forest untuk mendeteksi anomali lalu lintas jaringan.
- **Deep Packet Inspection (DPI)**: Menganalisis paket HTTP dan TLS/SSL secara mendalam.
- **Threat Intelligence Integration**: Menggunakan API AbuseIPDB untuk memeriksa apakah suatu IP terdeteksi sebagai ancaman global.
- **Honeytoken**: Mendeteksi akses ke honeypot yang digunakan untuk menarik serangan.
- **Log Enkripsi**: Mengenkripsi data log menggunakan algoritma AES dengan kunci yang dihasilkan secara aman.
- **Streamlit Dashboard**: Menampilkan statistik dan laporan ancaman melalui dashboard berbasis web.
- **Kafka Producer**: Mengirimkan data log ke Kafka untuk pemrosesan lebih lanjut.

## Instalasi

1. **Clone repository**:
    ```bash
    git clone https://github.com/Dimas-Alif/ids-ips.git
    cd ids-ips
    ```

2. **Install dependencies**:
    Pastikan Anda memiliki Python 3.7 atau lebih tinggi, kemudian instal semua dependensi berikut:
    ```bash
    pip install -r requirements.txt
    ```

3. **Buat file `.env`**:
    Buat file `.env` di direktori root proyek dan isi dengan informasi berikut:
    ```env
    ELASTICSEARCH_URL=http://localhost:9200
    KAFKA_SERVER=localhost:9092
    KAFKA_TOPIC=ids_topic
    ENCRYPTION_PASSWORD=your_encryption_password
    ABUSEIPDB_API_KEY=your_abuseipdb_api_key
    ```

4. **Jalankan sistem**:
    Anda dapat memilih berbagai opsi untuk menjalankan sistem:
    - **Menjalankan Snort**: 
        ```bash
        python ids_snort_integration.py
        ```
    - **Menganalisis lalu lintas jaringan real-time**:
        ```bash
        python ids_snort_integration.py
        ```
    - **Menampilkan dashboard dengan Streamlit**:
        ```bash
        streamlit run ids_snort_integration.py
        ```

## Struktur Direktori
    
    ids-ips/
    │
    ├── ids_snort_integration.py      # Skrip utama untuk menjalankan IDS/IPS
    ├── logs/                         # Folder untuk menyimpan log aktivitas IDS/IPS
    ├── snort_rules/                  # Folder untuk file konfigurasi Snort
    ├── ml_models/                    # Folder untuk model AI yang dilatih
    │   └── final_model.pkl           # Model AI yang dilatih
    ├── datasets/                     # Folder untuk dataset yang digunakan untuk pelatihan model AI
    │   └── realistic_attack_data.csv # Dataset serangan realistis
    ├── requirements.txt              # Daftar dependensi Python
    ├── .env                          # File untuk variabel lingkungan
    └── README.md                     # File dokumentasi ini
## Menjalankan Sistem

### 1. Jalankan Snort
Snort akan berjalan dalam mode logging untuk memantau lalu lintas jaringan dan mendeteksi ancaman. Anda dapat menjalankan Snort dengan perintah berikut:
    
      python ids_snort_integration.py

### 2. Tangkap lalu lintas jaringan
Setelah Snort dijalankan, Anda dapat menggunakan fitur untuk menangkap dan memproses paket secara real-time dengan menggunakan scapy. Berikut adalah cara untuk menjalankan pemrosesan paket:
   
    python ids_snort_integration.py
### 3. Latih model AI
Model deteksi anomali berbasis AI dilatih menggunakan dataset yang disediakan. Anda dapat melatih model dengan perintah:
   
    python ids_snort_integration.py

### 4. Tampilkan Dashboard dengan Streamlit
Gunakan Streamlit untuk menampilkan dashboard yang memberikan statistik ancaman dan log lalu lintas jaringan:

    streamlit run ids_snort_integration.py

## Pengaturan dan Konfigurasi
- Elasticsearch: Pastikan Anda telah menjalankan server Elasticsearch pada URL yang ditentukan dalam file .env.
- Kafka: Server Kafka harus aktif dan dikonfigurasi sesuai dengan pengaturan di file .env.
- Snort: Pastikan Snort telah diinstal dan dikonfigurasi dengan benar.

## Dependensi

- **scapy**: Untuk menangkap dan memproses paket jaringan.
- **pyshark**: Untuk analisis paket mendalam (DPI).
- **sklearn**: Untuk pelatihan model AI.
- **tensorflow**: Untuk model AI berbasis Keras.
- **requests**: Untuk komunikasi dengan API eksternal (AbuseIPDB).
- **elasticsearch**: Untuk menyimpan dan mencari log di Elasticsearch.
- **kafka-python**: Untuk pengelolaan Kafka.
- **cryptography**: Untuk enkripsi data log.
