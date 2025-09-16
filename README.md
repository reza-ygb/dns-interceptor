# DNS Interceptor

🔥 **Professional Network Security Analysis Tool** - Advanced MITM Framework for Cybersecurity Professionals

[![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)](https://github.com/reza-ygb/dns-interceptor)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## ⚡ Features

- 🎯 **ARP Spoofing & Network Discovery**
- 👁️  **Advanced Packet Interception** 
- 🔓 **SSL/TLS Traffic Analysis**
- 💀 **Credential Harvesting**
- 🌐 **DNS Monitoring & Spoofing**
- 💾 **PCAP Export** for Wireshark/Zeek
- 📊 **Memory Cache System**
- 📄 **Professional HTML Reporting**

## 🚀 Quick Install (One-Line)

```bash
curl -fsSL https://github.com/reza-ygb/dns-interceptor/releases/download/v2.0.1/install.sh | bash
```

## 🏷️ Install via APT (signed)

Official signed APT repository (no trusted=yes).

```bash
# 1) Add repository key (binary .gpg)
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://reza-ygb.github.io/dns-interceptor/keyring/dns-interceptor.gpg \
  | sudo tee /etc/apt/keyrings/dns-interceptor.gpg >/dev/null
sudo chmod 0644 /etc/apt/keyrings/dns-interceptor.gpg

# 2) Add APT source (stable/main)
echo "deb [signed-by=/etc/apt/keyrings/dns-interceptor.gpg] https://reza-ygb.github.io/dns-interceptor stable main" \
  | sudo tee /etc/apt/sources.list.d/dns-interceptor.list >/dev/null

# 3) Update and install
sudo apt update
sudo apt install dns-interceptor
```

Verify key fingerprint (optional but recommended):

```bash
curl -fsSL https://reza-ygb.github.io/dns-interceptor/keyring/KEY.asc \
  | gpg --show-keys --with-fingerprint --keyid-format LONG
# Expected fingerprint:
# 0CDF 9B89 F572 1F36 4263  EE59 E0A9 C376 7CB3 A436
```

Key details:
- UID: dns-interceptor APT Signing <packages@reza-ygb.github.io>
- Algo/Size: RSA 4096
- Expires: 2027-09-16

## 📦 Manual Installation

```bash
# Clone repository
git clone https://github.com/reza-ygb/dns-interceptor.git
cd dns-interceptor

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x dns_interceptor.py
```

## 🎯 Usage Examples

### Network Discovery (Safe Mode)
```bash
sudo python3 dns_interceptor.py -i eth0 --discovery-only
```

### Passive Traffic Analysis
```bash
sudo python3 dns_interceptor.py -i eth0 --intercept-only --save-pcap capture.pcap
```

### Single Target Attack
```bash
sudo python3 dns_interceptor.py -i eth0 -t 192.168.1.100 -g 192.168.1.1 --attack
```

### Ultimate Mode (ARP + Interception)
```bash
sudo python3 dns_interceptor.py -i eth0 -t 192.168.1.100 -g 192.168.1.1 --ultimate-mode
```

### Credential Harvesting
```bash
sudo python3 dns_interceptor.py -i eth0 --credential-harvest --export-cache
```

### Mass Network Attack (⚠️ DANGEROUS)
```bash
sudo python3 dns_interceptor.py -i eth0 --mass-attack
```

## 🛠️ Command Line Options

```
Required:
  -i, --interface       Network interface (eth0, wlan0, etc.)

Target Specification:
  -t, --target-ip       Target IP address
  -g, --gateway-ip      Gateway/Router IP address

Operation Modes:
  --discovery-only      🔍 Safe network discovery
  --intercept-only      👁️  Passive packet analysis
  --attack             ⚠️  Single target ARP attack
  --ultimate-mode      💀 ARP attack + packet interception
  --credential-harvest  🔓 Aggressive credential hunting
  --mass-attack        💥 Network-wide attack (DANGEROUS)

Output Options:
  --save-pcap FILE     💾 Save packets to PCAP file
  --export-cache       📊 Export session data (JSON/CSV/TXT)
  --generate-report    📄 Generate HTML report
```

## 🔧 Requirements

- **Python 3.8+**
- **Root privileges** (for raw socket access)
- **Linux/macOS** (recommended)

## 📋 Dependencies

```bash
pip3 install scapy
```

## 🎨 Output Formats

### PCAP Export
- Compatible with **Wireshark**, **Zeek**, **TCPdump**
- Full packet capture for forensic analysis

### Cache Export  
- **JSON**: Structured data for APIs
- **CSV**: Spreadsheet-compatible format
- **TXT**: Human-readable summaries

### Memory Cache Features
- Real-time packet analysis
- DNS query tracking
- Credential detection
- Host discovery
- Session statistics

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing** and **educational purposes** only. 

- ✅ **Authorized penetration testing**
- ✅ **Security research on own networks**  
- ✅ **Educational cybersecurity training**
- ❌ **Unauthorized network attacks**
- ❌ **Malicious activities**

Users are responsible for compliance with applicable laws and regulations.

## 🔒 Ethical Usage

- Always obtain **written authorization** before testing
- Use only on **networks you own** or have permission to test
- Follow **responsible disclosure** for vulnerabilities
- Respect **privacy** and **data protection** laws

## 📊 Example Output

```
🔥 DNS Interceptor v2.0.0 - Professional Network Security Tool 🔥
⚡ Advanced MITM Framework for Cybersecurity Professionals
🎯 ARP Spoofing | Packet Analysis | Credential Harvesting
💀 SSL Strip | DNS Spoofing | PCAP Export | Memory Cache

🌐 [INTERFACE] Using: eth0
🖥️  [LOCAL-IP] Your IP: 192.168.1.50

👁️  [INTERCEPT] Advanced packet analysis with caching...
🔍 [HUNTING] Credentials, tokens, cookies, files...
💾 [PCAP] Saving packets to: capture.pcap
🚀 [LIVE] Advanced packet interception active...

🌐 [22:41:30] DNS: 192.168.1.100 → google.com
🔒 [22:41:31] SSL HANDSHAKE: 192.168.1.100 → 142.250.191.14
🔓 [22:41:32] *** CREDENTIAL CAPTURED! ***
    🎯 Source: 192.168.1.100:54321
    🎯 Target: 10.0.0.5:80
    🔑 Pattern: PASSWORD=
    📄 Data: POST /login HTTP/1.1...

📊 [STATS] Packets: 1250 | Passwords: 3 | DNS: 95 | Tokens: 12
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎓 Educational Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cybersecurity)
- [Scapy Documentation](https://scapy.readthedocs.io/)

## 🔗 Related Projects

- [Ettercap](https://www.ettercap-project.org/) - Comprehensive MITM framework
- [Bettercap](https://www.bettercap.org/) - Modern network attack framework
- [MITMproxy](https://mitmproxy.org/) - Interactive HTTPS proxy

## 📞 Support

- 📧 **Email**: yaghobpoor@khu.ac.ir

⭐ **Star this repository** if you find it useful for your cybersecurity work!
