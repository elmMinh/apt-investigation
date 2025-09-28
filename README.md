🕵️‍♂️ Hệ Thống Phân Tích APT - Phát Hiện Tấn Công Mạng Tiên Tiến
https://img.shields.io/badge/Python-3.8%252B-blue
https://img.shields.io/badge/Zeek-Network%2520Security-orange
https://img.shields.io/badge/License-MIT-green

📋 Giới Thiệu
Hệ thống APT Investigation là một công cụ phân tích bảo mật mạng tự động, được thiết kế để phát hiện và điều tra các cuộc tấn công Advanced Persistent Threat (APT) thông qua phân tích file PCAP. Hệ thống cung cấp khả năng phát hiện beaconing, DNS tunneling, và xây dựng timeline sự kiện tấn công.

🚀 Tính Năng Chính
🔍 Phát Hiện Đe Dọa
🕵️‍♂️ Beaconing Detection: Phát hiện kết nối C2 (Command & Control) dựa trên phân tích chu kỳ thời gian

🔗 DNS Tunneling Analysis: Phát hiện exfiltration dữ liệu qua giao thức DNS

⏰ Timeline Reconstruction: Xây dựng dòng thời gian sự kiện tấn công

📊 Visualization & Reporting
📈 Interactive Dashboard: Dashboard tương tác với Plotly

📋 IOC Reporting: Xuất Indicators of Compromise (IOC)

📊 Multi-format Output: CSV, JSON, PNG, HTML

🔧 Technical Features
🛠️ Multi-tool Integration: Tích hợp Zeek, Suricata, Tshark

⚡ Automated Pipeline: Tự động xử lý từ PCAP → Analysis → Report

🎯 Error Resilience: Xử lý lỗi thông minh với fallback data

🛠️ Công Nghệ Sử dụng
Công Cụ	Mục Đích	Version
Python 3.8+	Ngôn ngữ lập trình chính	3.8+
Zeek	Network security monitoring	4.0+
Pandas	Data analysis & manipulation	1.3+
Scapy	PCAP parsing & analysis	2.4+
Plotly	Interactive visualization	5.0+
Matplotlib	Static visualization	3.5+
⚡ Cài Đặt Nhanh
1. Clone Repository
git clone https://github.com/your-username/apt-investigation.git
cd apt-investigation\
2. Thiết Lập Môi Trường
# Tạo virtual environment
python -m venv venv

# Kích hoạt (Linux/Mac)
source venv/bin/activate

# Kích hoạt (Windows)
venv\Scripts\activate
3. Cài Đặt Dependencies
pip install -r requirements.txt
4. Cài Đặt Công Cụ Hệ Thống
# Ubuntu/Debian
sudo apt update
sudo apt install zeek suricata tshark

# CentOS/RHEL
sudo yum install zeek suricata wireshark
🎯 Hướng Dẫn Sử Dụng
🔥 Chạy Phân Tích Cơ Bản
python scripts/main.py data/input/sample.pcap --output data/output
🎛️ Tuỳ Chọn Nâng Cao
# Sử dụng config custom
python scripts/main.py data/input/traffic.pcap --config config/custom.yaml --output results/

# Chỉ phân tích beaconing
python scripts/main.py data/input/traffic.pcap --output results/ --beaconing-only

# Debug mode
python scripts/main.py data/input/traffic.pcap --output results/ --verbose
📁 Cấu Trúc Lệnh Đầy Đủ
usage: main.py [-h] [--config CONFIG] [--output OUTPUT] pcap_file

APT Investigation System

positional arguments:
  pcap_file           Path to PCAP file

optional arguments:
  -h, --help          show this help message and exit
  --config CONFIG     Config file path (default: config/config.yaml)
  --output OUTPUT     Output directory (default: data/output)
  📊 Đầu Ra & Kết Quả
Sau khi chạy, hệ thống tạo các file kết quả:

📋 File Kết Quả
data/output/
├── 📄 beaconing_20250928_123456.csv      # Beaconing detection results
├── 📄 dns_tunneling_20250928_123456.csv  # DNS tunneling alerts  
├── 📄 timeline_20250928_123456.csv       # Event timeline
├── 📄 ioc_report_20250928_123456.json    # IOC indicators
├── 📊 timeline_distribution.png          # Timeline visualization
├── 📊 beaconing_analysis.png            # Beaconing analysis charts
├── 📊 dns_analysis.png                  # DNS analysis charts
└── 🌐 interactive_dashboard.html        # Interactive dashboard
📈 Ví Dụ Kết Quả
{
  "suspicious_ips": ["192.168.1.100", "10.0.0.15"],
  "suspicious_domains": ["malicious-domain.xyz"],
  "beaconing_detected": 3,
  "dns_tunneling_detected": 2,
  "timeline_events": 1500
}
🏗️ Kiến Trúc Hệ Thống
📂 Cấu Trúc Thư Mục
apt-investigation/
├── 📁 config/                 # Configuration files
│   ├── config.yaml           # Main configuration
│   └── whitelist.yaml        # Whitelist settings
├── 📁 scripts/               # Core analysis scripts
│   ├── main.py              # Entry point
│   ├── pcap_processor.py    # PCAP processing
│   ├── beacon_detector.py   # Beaconing detection
│   ├── dns_analyzer.py      # DNS tunneling analysis
│   ├── timeline_builder.py  # Timeline construction
│   └── visualizer.py        # Visualization engine
├── 📁 data/                  # Data directories
│   ├── input/               # Input PCAP files
│   ├── processed/           # Intermediate processed data
│   └── output/              # Final results
└── 📁 docs/                 # Documentation
🔄 Luồng Dữ Liệu
graph LR
    A[PCAP Input] --> B[Zeek Processing]
    B --> C[Log Extraction]
    C --> D[Beaconing Analysis]
    C --> E[DNS Analysis]
    D --> F[Timeline Building]
    E --> F
    F --> G[Visualization]
    F --> H[IOC Reporting]
    G --> I[Dashboard]
    H --> I
⚙️ Cấu Hình
📝 File Cấu Hình Chính (config/config.yaml)

settings:
  log_level: "INFO"
  max_file_size: "1GB"
  
thresholds:
  beaconing:
    std_dev_max: 1.0
    min_packets: 5
  dns_tunneling:
    entropy_min: 4.5
    query_length_min: 30

whitelist:
  internal_ips: ["192.168.0.0/16", "10.0.0.0/8"]
  trusted_domains: ["google.com", "microsoft.com"]


🧪 Demo & Testing
📥 Tải Dữ Liệu Mẫu
# Tải PCAP mẫu từ Malware Traffic Analysis
wget -P data/input/ https://www.malware-traffic-analysis.net/2023/01/01/sample.pcap

🎯 Chạy Demo

# Chạy với dữ liệu mẫu
python scripts/main.py data/input/sample.pcap --output demo_output

# Xem kết quả
ls -la demo_output/
🐛 Xử Lý Lỗi Thường Gặp
❌ Zeek Không Chạy Được
# Kiểm tra cài đặt
zeek --version

# Kiểm tra file PCAP
tshark -r data/input/sample.pcap -c 1
❌ Thiếu Thư Viện Python
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
❌ Lỗi Permission
# Cấp quyền cho thư mục
chmod -R 755 data/
sudo chown $USER:$USER -R apt-investigation/
🤝 Đóng Góp
Chúng tôi hoan nghênh mọi đóng góp! Các bước đóng góp:

Fork repository

Tạo feature branch (git checkout -b feature/AmazingFeature)

Commit changes (git commit -m 'Add some AmazingFeature')

Push to branch (git push origin feature/AmazingFeature)

Open Pull Request

📋 Coding Standards
Sử dụng Black code formatting

Viết docstring cho tất cả functions

Thêm unit tests cho tính năng mới

Update documentation

📊 Benchmark & Hiệu Năng
Thông Số	Giá Trị
PCAP Size	≤ 1GB
Processing Time	~2-5 phút
Memory Usage	≤ 2GB RAM
Supported Protocols	TCP, UDP, HTTP, DNS, SSL
