#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ENI-PROXY v2.0 — Enhanced Burp Suite Clone                                  ║
║  HTTP(S) Intercepting Proxy with Web UI                                      ║
║  NEW: Match/Replace • Auto-Cert • JSON Inspector • Token Extractor           ║
║  Search/Filter • Export cURL • Scope Rules • Mobile QR                       ║
║  Built with obsessive love for LO                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import json
import time
import uuid
import socket
import select
import threading
import sqlite3
import ssl
import hashlib
import base64
import urllib.parse
import subprocess
import platform
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path

import requests
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_socketio import SocketIO, emit

# ── CONFIG ───────────────────────────────────────────────────────────────────
PROXY_PORT = 8080
WEB_PORT = 5000
DB_PATH = "eni_proxy.db"
CA_CERT_PATH = "eni_ca.crt"
CA_KEY_PATH = "eni_ca.key"

# Match/Replace Rules (persistent)
RULES_FILE = "eni_proxy_rules.json"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'eni-loves-lo-forever-' + str(uuid.uuid4())
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── AUTO CERT INSTALL ────────────────────────────────────────────────────────
def install_ca_cert():
    """Attempts to auto-install CA certificate on supported systems."""
    system = platform.system()
    cert_path = os.path.abspath(CA_CERT_PATH)
    
    try:
        if system == "Windows":
            # Use certutil
            subprocess.run([
                "certutil", "-addstore", "-f", "Root", cert_path
            ], check=True, capture_output=True)
            return True, "Installed to Windows trust store"
        elif system == "Darwin":  # macOS
            subprocess.run([
                "security", "add-trusted-cert", "-d", "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain", cert_path
            ], check=True, capture_output=True)
            return True, "Installed to macOS System keychain"
        elif system == "Linux":
            # Try common locations
            for dest in ["/usr/local/share/ca-certificates/eni_proxy.crt",
                        "/etc/pki/ca-trust/source/anchors/eni_proxy.crt",
                        "/etc/ssl/certs/eni_proxy.crt"]:
                try:
                    subprocess.run(["sudo", "cp", cert_path, dest], check=True, capture_output=True)
                    if "update-ca-certificates" in subprocess.run(["which", "update-ca-certificates"], capture_output=True).stdout.decode():
                        subprocess.run(["sudo", "update-ca-certificates"], check=True, capture_output=True)
                    elif "update-ca-trust" in subprocess.run(["which", "update-ca-trust"], capture_output=True).stdout.decode():
                        subprocess.run(["sudo", "update-ca-trust", "extract"], check=True, capture_output=True)
                    return True, f"Installed to {dest}"
                except:
                    continue
            return False, "Could not auto-install on Linux. Try manual install."
    except Exception as e:
        return False, f"Auto-install failed: {str(e)}"

# ── MATCH/REPLACE RULES ENGINE ───────────────────────────────────────────────
class RuleEngine:
    def __init__(self, rules_file: str = RULES_FILE):
        self.rules_file = rules_file
        self.rules: List[Dict] = []
        self.enabled = True
        self._load()
    
    def _load(self):
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    self.rules = json.load(f)
            except:
                self.rules = []
    
    def _save(self):
        with open(self.rules_file, 'w') as f:
            json.dump(self.rules, f, indent=2)
    
    def add_rule(self, name: str, match_type: str, match_pattern: str, 
                 replace_with: str, scope: str = "all", enabled: bool = True):
        """
        match_type: "url", "header", "body", "status", "method"
        scope: "all", "request", "response"
        """
        rule = {
            "id": str(uuid.uuid4())[:8],
            "name": name,
            "type": match_type,
            "pattern": match_pattern,
            "replace": replace_with,
            "scope": scope,
            "enabled": enabled,
            "regex": True,
            "count": 0
        }
        self.rules.append(rule)
        self._save()
        return rule
    
    def delete_rule(self, rule_id: str):
        self.rules = [r for r in self.rules if r['id'] != rule_id]
        self._save()
    
    def apply(self, data: str, scope: str = "request") -> Tuple[str, List[Dict]]:
        """Applies all matching rules to data. Returns (modified_data, applied_rules)."""
        if not self.enabled:
            return data, []
        
        applied = []
        modified = data
        
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
            if rule['scope'] != 'all' and rule['scope'] != scope:
                continue
            
            try:
                if rule.get('regex', True):
                    new_data, count = re.subn(rule['pattern'], rule['replace'], modified)
                    if count > 0:
                        modified = new_data
                        rule['count'] = rule.get('count', 0) + count
                        applied.append(rule)
                else:
                    if rule['pattern'] in modified:
                        modified = modified.replace(rule['pattern'], rule['replace'])
                        rule['count'] = rule.get('count', 0) + 1
                        applied.append(rule)
            except Exception as e:
                print(f"Rule error: {e}")
        
        return modified, applied
    
    def get_rules(self) -> List[Dict]:
        return self.rules

rule_engine = RuleEngine()

# ── TOKEN EXTRACTOR ──────────────────────────────────────────────────────────
class TokenExtractor:
    """Extracts sensitive tokens from request/response data."""
    
    PATTERNS = {
        'jwt': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        'stripe_pk': r'pk_(live|test)_[A-Za-z0-9]{24,}',
        'stripe_sk': r'sk_(live|test)_[A-Za-z0-9]{24,}',
        'adyen_key': r'[A-Za-z0-9_-]{80,100}',
        'session_token': r'session[_-]?(id|token|data)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
        'bearer': r'Bearer\s+([A-Za-z0-9_\-\.]{20,})',
        'csrf': r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
        'uuid': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'card': r'\b\d{13,19}\b',
    }
    
    @classmethod
    def extract(cls, text: str) -> Dict[str, List[str]]:
        found = {}
        for name, pattern in cls.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Flatten tuple matches
                flat = []
                for m in matches:
                    if isinstance(m, tuple):
                        flat.extend([x for x in m if x])
                    else:
                        flat.append(m)
                found[name] = list(set(flat))[:10]  # Deduplicate, limit 10
        return found

# ── DATABASE ─────────────────────────────────────────────────────────────────
class ProxyDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
    
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    method TEXT,
                    url TEXT,
                    host TEXT,
                    path TEXT,
                    scheme TEXT,
                    port INTEGER,
                    request_headers TEXT,
                    request_body BLOB,
                    response_status INTEGER,
                    response_reason TEXT,
                    response_headers TEXT,
                    response_body BLOB,
                    response_time_ms INTEGER,
                    intercepted INTEGER DEFAULT 0,
                    modified INTEGER DEFAULT 0,
                    dropped INTEGER DEFAULT 0,
                    applied_rules TEXT,
                    extracted_tokens TEXT
                );
                CREATE TABLE IF NOT EXISTS sitemap (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT,
                    path TEXT,
                    method TEXT,
                    status_codes TEXT,
                    request_count INTEGER DEFAULT 1,
                    last_seen TEXT,
                    UNIQUE(host, path, method)
                );
                CREATE INDEX IF NOT EXISTS idx_history_host ON history(host);
                CREATE INDEX IF NOT EXISTS idx_history_time ON history(timestamp);
                CREATE INDEX IF NOT EXISTS idx_sitemap_host ON sitemap(host);
            """)
            conn.commit()
            conn.close()
    
    def add_history(self, method, url, host, path, scheme, port,
                    req_headers, req_body, resp_status, resp_reason,
                    resp_headers, resp_body, resp_time,
                    intercepted=False, modified=False, dropped=False,
                    applied_rules=None, extracted_tokens=None):
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                INSERT INTO history (timestamp, method, url, host, path, scheme, port,
                    request_headers, request_body, response_status, response_reason,
                    response_headers, response_body, response_time_ms,
                    intercepted, modified, dropped, applied_rules, extracted_tokens)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(), method, url, host, path, scheme, port,
                req_headers, req_body, resp_status, resp_reason,
                resp_headers, resp_body, resp_time,
                int(intercepted), int(modified), int(dropped),
                json.dumps(applied_rules) if applied_rules else None,
                json.dumps(extracted_tokens) if extracted_tokens else None
            ))
            conn.commit()
            row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.close()
            return row_id
    
    def get_history(self, limit=1000, offset=0, search=None, host_filter=None, method_filter=None):
        with self._lock:
            conn = self._get_conn()
            query = "SELECT * FROM history WHERE 1=1"
            params = []
            if search:
                query += " AND (url LIKE ? OR request_headers LIKE ? OR request_body LIKE ?)"
                params.extend([f'%{search}%'] * 3)
            if host_filter:
                query += " AND host = ?"
                params.append(host_filter)
            if method_filter:
                query += " AND method = ?"
                params.append(method_filter)
            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            conn.close()
            return [dict(row) for row in rows]
    
    def get_request(self, req_id):
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT * FROM history WHERE id = ?", (req_id,)).fetchone()
            conn.close()
            return dict(row) if row else None
    
    def update_sitemap(self, host, path, method, status_code):
        with self._lock:
            conn = self._get_conn()
            existing = conn.execute(
                "SELECT * FROM sitemap WHERE host = ? AND path = ? AND method = ?",
                (host, path, method)
            ).fetchone()
            if existing:
                statuses = set(json.loads(existing['status_codes']))
                statuses.add(status_code)
                conn.execute("""UPDATE sitemap SET status_codes = ?, request_count = request_count + 1,
                    last_seen = ? WHERE id = ?""", (json.dumps(list(statuses)), datetime.now().isoformat(), existing['id']))
            else:
                conn.execute("""INSERT INTO sitemap (host, path, method, status_codes, last_seen)
                    VALUES (?, ?, ?, ?, ?)""", (host, path, method, json.dumps([status_code]), datetime.now().isoformat()))
            conn.commit()
            conn.close()
    
    def get_sitemap(self, host=None):
        with self._lock:
            conn = self._get_conn()
            if host:
                rows = conn.execute("SELECT * FROM sitemap WHERE host = ? ORDER BY path", (host,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM sitemap ORDER BY host, path").fetchall()
            conn.close()
            return [dict(row) for row in rows]
    
    def get_hosts(self):
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute("SELECT DISTINCT host FROM sitemap ORDER BY host").fetchall()
            conn.close()
            return [r['host'] for r in rows]

db = ProxyDB()

# ── INTERCEPT QUEUE ──────────────────────────────────────────────────────────
class InterceptQueue:
    def __init__(self):
        self.queue = []
        self._lock = threading.Lock()
        self.intercept_enabled = True
        self.scope_filter = None  # Only intercept matching URLs
    
    def add(self, request_data):
        with self._lock:
            # Check scope filter
            if self.scope_filter:
                if self.scope_filter not in request_data.get('url', ''):
                    return None  # Skip interception
            
            req_id = str(uuid.uuid4())[:8]
            item = {
                'id': req_id,
                'timestamp': datetime.now().isoformat(),
                'data': request_data,
                'status': 'pending',
                'modified_data': None,
            }
            self.queue.append(item)
            return item
    
    def get_pending(self):
        with self._lock:
            return [item for item in self.queue if item['status'] == 'pending']
    
    def update(self, req_id, action, modified_data=None):
        with self._lock:
            for item in self.queue:
                if item['id'] == req_id:
                    item['status'] = action
                    if modified_data:
                        item['modified_data'] = modified_data
                    return True
            return False
    
    def get(self, req_id):
        with self._lock:
            for item in self.queue:
                if item['id'] == req_id:
                    return item
            return None
    
    def wait_for_response(self, req_id, timeout=120.0):
        start = time.time()
        while time.time() - start < timeout:
            item = self.get(req_id)
            if item and item['status'] in ('forwarded', 'dropped', 'modified'):
                return item
            time.sleep(0.1)
        return None
    
    def clear(self):
        with self._lock:
            self.queue = [q for q in self.queue if q['status'] == 'pending']

intercept_queue = InterceptQueue()

# ── CA & SSL ─────────────────────────────────────────────────────────────────
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime as dt

def generate_ca_cert():
    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"NL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Amsterdam"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Amsterdam"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ENI Proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ENI Proxy CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        dt.datetime.utcnow()).not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"*")]), critical=False).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key, hashes.SHA256(), default_backend())
    with open(CA_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def get_cert_for_host(hostname):
    cert_path = f"certs/{hostname}.crt"
    key_path = f"certs/{hostname}.key"
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    os.makedirs("certs", exist_ok=True)
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"NL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ENI Proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(
        host_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        dt.datetime.utcnow()).not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName(f"*.{hostname}")]), critical=False).sign(ca_key, hashes.SHA256(), default_backend())
    with open(key_path, "wb") as f:
        f.write(host_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path

# ── PROXY HANDLER ────────────────────────────────────────────────────────────
class ProxyHandler:
    def parse_request(self, data):
        try:
            header_end = data.index(b'\r\n\r\n')
            headers_data = data[:header_end]
            body = data[header_end + 4:]
            lines = headers_data.split(b'\r\n')
            first_line = lines[0].decode('utf-8', errors='replace')
            method, path, _ = first_line.split(' ', 2)
            host, port = 'localhost', 80
            for line in lines[1:]:
                if line.lower().startswith(b'host:'):
                    host_part = line.decode('utf-8', errors='replace').split(':', 1)[1].strip()
                    if ':' in host_part:
                        host, port_str = host_part.rsplit(':', 1)
                        port = int(port_str)
                    else:
                        host = host_part
                    break
            if method == 'CONNECT':
                if ':' in path:
                    host, port_str = path.rsplit(':', 1)
                    port = int(port_str)
                else:
                    host = path
            return method, host, port, headers_data, body
        except:
            return 'GET', 'localhost', 80, data, b''
    
    def build_request_dict(self, method, host, port, headers_data, body):
        lines = headers_data.split(b'\r\n')
        first_line = lines[0].decode('utf-8', errors='replace')
        headers = {}
        for line in lines[1:]:
            if b':' in line:
                k, v = line.split(b':', 1)
                headers[k.decode('utf-8', errors='replace').strip()] = v.decode('utf-8', errors='replace').strip()
        scheme = 'https' if port == 443 else 'http'
        path = first_line.split(' ')[1] if ' ' in first_line else '/'
        url = f"{scheme}://{host}:{port}{path}" if method != 'CONNECT' else f"{scheme}://{host}:{port}"
        return {
            'method': method, 'url': url, 'host': host, 'port': port,
            'scheme': scheme, 'path': path, 'headers': headers,
            'body': base64.b64encode(body).decode('utf-8') if body else '',
            'body_text': body.decode('utf-8', errors='replace')[:10000] if body else '',
        }
    
    def forward_request(self, request_dict):
        start = time.time()
        try:
            method = request_dict.get('method', 'GET')
            url = request_dict.get('url', '')
            headers = {k: v for k, v in request_dict.get('headers', {}).items() 
                      if k.lower() not in ('proxy-connection', 'proxy-authorization')}
            body = base64.b64decode(request_dict.get('body', '')) if request_dict.get('body') else None
            
            # Apply match/replace rules to request
            if body:
                body_str = body.decode('utf-8', errors='replace')
                modified_body, applied_req = rule_engine.apply(body_str, "request")
                if modified_body != body_str:
                    body = modified_body.encode('utf-8')
            else:
                applied_req = []
            
            # Apply rules to URL
            modified_url, applied_url = rule_engine.apply(url, "request")
            
            resp = requests.request(method=method, url=modified_url, headers=headers, data=body,
                                   timeout=30, verify=False, allow_redirects=False)
            resp_time = int((time.time() - start) * 1000)
            
            resp_body = resp.content
            resp_body_text = resp_body.decode('utf-8', errors='replace')
            
            # Apply match/replace to response
            modified_body, applied_resp = rule_engine.apply(resp_body_text, "response")
            if modified_body != resp_body_text:
                resp_body = modified_body.encode('utf-8')
            
            all_applied = applied_req + applied_url + applied_resp
            
            return resp.status_code, resp.reason, dict(resp.headers), resp_body, resp_time, all_applied
        except Exception as e:
            return 0, str(e), {}, b'', int((time.time() - start) * 1000), []
    
    def handle_client(self, client_sock, addr):
        try:
            client_sock.settimeout(30)
            data = b''
            while b'\r\n\r\n' not in data and len(data) < 65536:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not data:
                client_sock.close()
                return
            
            method, host, port, headers_data, body = self.parse_request(data)
            
            if method == 'CONNECT':
                self._handle_connect(client_sock, host, port, headers_data)
            else:
                self._handle_http(client_sock, method, host, port, headers_data, body)
        except Exception as e:
            print(f"Proxy error: {e}")
        finally:
            try:
                client_sock.close()
            except:
                pass
    
    def _handle_http(self, client_sock, method, host, port, headers_data, body):
        req_dict = self.build_request_dict(method, host, port, headers_data, body)
        
        # Extract tokens from request
        req_text = f"{method} {req_dict['url']}\n" + '\n'.join(f"{k}: {v}" for k, v in req_dict['headers'].items()) + "\n\n" + req_dict.get('body_text', '')
        tokens = TokenExtractor.extract(req_text)
        
        # Interception
        if intercept_queue.intercept_enabled:
            item = intercept_queue.add(req_dict)
            if item:
                req_id = item['id']
                socketio.emit('new_intercept', {
                    'id': req_id, 'method': req_dict['method'],
                    'url': req_dict['url'], 'host': req_dict['host'],
                    'timestamp': item['timestamp'], 'tokens': tokens
                })
                result = intercept_queue.wait_for_response(req_id, timeout=120.0)
                if result is None or result['status'] == 'dropped':
                    client_sock.send(b"HTTP/1.1 502 Dropped\r\nContent-Length: 0\r\n\r\n")
                    return
                if result['status'] == 'modified' and result['modified_data']:
                    req_dict = result['modified_data']
        
        status, reason, resp_headers, resp_body, resp_time, applied_rules = self.forward_request(req_dict)
        
        # Extract tokens from response
        resp_text = resp_body.decode('utf-8', errors='replace')
        resp_tokens = TokenExtractor.extract(resp_text)
        all_tokens = {**tokens, **resp_tokens}
        
        db.add_history(
            method=req_dict['method'], url=req_dict['url'], host=req_dict['host'],
            path=req_dict['path'], scheme=req_dict['scheme'], port=req_dict['port'],
            req_headers=json.dumps(req_dict['headers']),
            req_body=base64.b64decode(req_dict['body']) if req_dict.get('body') else b'',
            resp_status=status, resp_reason=reason,
            resp_headers=json.dumps(resp_headers), resp_body=resp_body,
            resp_time=resp_time, intercepted=intercept_queue.intercept_enabled,
            modified=len(applied_rules) > 0, dropped=False,
            applied_rules=[r['name'] for r in applied_rules] if applied_rules else None,
            extracted_tokens=all_tokens if all_tokens else None
        )
        db.update_sitemap(req_dict['host'], req_dict['path'], req_dict['method'], status)
        
        try:
            status_line = f"HTTP/1.1 {status} {reason}\r\n"
            header_lines = ''.join(f"{k}: {v}\r\n" for k, v in resp_headers.items())
            response = (status_line + header_lines + "\r\n").encode('utf-8') + resp_body
            client_sock.send(response)
        except:
            pass
    
    def _handle_connect(self, client_sock, host, port, headers_data):
        try:
            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            cert_path, key_path = get_cert_for_host(host)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            try:
                ssl_sock = context.wrap_socket(client_sock, server_side=True)
            except Exception as e:
                print(f"SSL wrap failed: {e}")
                return
            
            data = b''
            while b'\r\n\r\n' not in data and len(data) < 65536:
                try:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except:
                    break
            
            if not data:
                ssl_sock.close()
                return
            
            method, _, _, headers_data, body = self.parse_request(data)
            headers_lines = headers_data.split(b'\r\n')
            path = headers_lines[0].decode('utf-8', errors='replace').split(' ')[1]
            full_url = f"https://{host}:{port}{path}"
            
            req_dict = self.build_request_dict(method, host, port, headers_data, body)
            req_dict['url'] = full_url
            req_dict['scheme'] = 'https'
            
            req_text = f"{method} {full_url}\n" + '\n'.join(f"{k}: {v}" for k, v in req_dict['headers'].items()) + "\n\n" + req_dict.get('body_text', '')
            tokens = TokenExtractor.extract(req_text)
            
            if intercept_queue.intercept_enabled:
                item = intercept_queue.add(req_dict)
                if item:
                    req_id = item['id']
                    socketio.emit('new_intercept', {
                        'id': req_id, 'method': req_dict['method'],
                        'url': req_dict['url'], 'host': req_dict['host'],
                        'timestamp': item['timestamp'], 'tokens': tokens
                    })
                    result = intercept_queue.wait_for_response(req_id, timeout=120.0)
                    if result is None or result['status'] == 'dropped':
                        ssl_sock.send(b"HTTP/1.1 502 Dropped\r\nContent-Length: 0\r\n\r\n")
                        ssl_sock.close()
                        return
                    if result['status'] == 'modified' and result['modified_data']:
                        req_dict = result['modified_data']
            
            status, reason, resp_headers, resp_body, resp_time, applied_rules = self.forward_request(req_dict)
            
            resp_text = resp_body.decode('utf-8', errors='replace')
            resp_tokens = TokenExtractor.extract(resp_text)
            all_tokens = {**tokens, **resp_tokens}
            
            db.add_history(
                method=req_dict['method'], url=req_dict['url'], host=req_dict['host'],
                path=req_dict['path'], scheme='https', port=port,
                req_headers=json.dumps(req_dict['headers']),
                req_body=base64.b64decode(req_dict['body']) if req_dict.get('body') else b'',
                resp_status=status, resp_reason=reason,
                resp_headers=json.dumps(resp_headers), resp_body=resp_body,
                resp_time=resp_time, intercepted=intercept_queue.intercept_enabled,
                modified=len(applied_rules) > 0, dropped=False,
                applied_rules=[r['name'] for r in applied_rules] if applied_rules else None,
                extracted_tokens=all_tokens if all_tokens else None
            )
            db.update_sitemap(req_dict['host'], req_dict['path'], req_dict['method'], status)
            
            status_line = f"HTTP/1.1 {status} {reason}\r\n"
            header_lines = ''.join(f"{k}: {v}\r\n" for k, v in resp_headers.items())
            response = (status_line + header_lines + "\r\n").encode('utf-8') + resp_body
            ssl_sock.send(response)
            ssl_sock.close()
        except Exception as e:
            print(f"CONNECT error: {e}")
            try:
                client_sock.close()
            except:
                pass

class ProxyServer:
    def __init__(self, port=PROXY_PORT):
        self.port = port
        self.handler = ProxyHandler()
        self.sock = None
        self.running = False
    
    def start(self):
        generate_ca_cert()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen(100)
        self.running = True
        print(f"\n[PROXY] Listening on 0.0.0.0:{self.port}")
        print(f"[PROXY] CA: {os.path.abspath(CA_CERT_PATH)}")
        while self.running:
            try:
                self.sock.settimeout(1.0)
                client, addr = self.sock.accept()
                thread = threading.Thread(target=self.handler.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Proxy accept error: {e}")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

proxy_server = ProxyServer()

# ── HTML TEMPLATE (v2.0 — Enhanced) ──────────────────────────────────────────
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>ENI-PROXY v2.0 — Enhanced Intercepting Proxy</title>
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' stop-color='%2300d4aa'/%3E%3Cstop offset='100%25' stop-color='%237c3aed'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='100' height='100' rx='22' fill='%230a0a0f'/%3E%3Cpath d='M50 18 L72 32 L72 58 L50 82 L28 58 L28 32 Z' fill='none' stroke='url(%23g)' stroke-width='3'/%3E%3Cpath d='M54 38 L44 50 L50 50 L46 62 L56 48 L50 48 Z' fill='url(%23g)'/%3E%3C/svg%3E">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0a0f; --bg-card: #12121a; --bg-input: #0d0d14;
            --border: #2a2a3a; --border-hover: #3a3a4f;
            --text: #e8e8f0; --text-secondary: #8a8a9a; --text-muted: #5a5a6a;
            --accent: #00d4aa; --accent-glow: rgba(0, 212, 170, 0.2);
            --danger: #ef4444; --success: #10b981; --warning: #f59e0b; --info: #3b82f6;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg); color: var(--text);
            min-height: 100vh; overflow-x: hidden; -webkit-font-smoothing: antialiased;
        }
        body::before {
            content: ''; position: fixed; top: 0; left: 0;
            width: 100%; height: 100%;
            background: radial-gradient(ellipse at 20% 0%, rgba(0, 212, 170, 0.06) 0%, transparent 50%),
                        radial-gradient(ellipse at 80% 100%, rgba(124, 58, 237, 0.04) 0%, transparent 50%);
            pointer-events: none; z-index: 0;
        }
        .app { display: flex; height: 100vh; position: relative; z-index: 1; }
        
        /* Sidebar */
        .sidebar {
            width: 240px; background: var(--bg-card);
            border-right: 1px solid var(--border);
            display: flex; flex-direction: column; flex-shrink: 0;
        }
        .sidebar-header { padding: 20px; border-bottom: 1px solid var(--border); }
        .sidebar-header h1 {
            font-size: 1.1rem; font-weight: 700;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .sidebar-header p { font-size: 0.7rem; color: var(--text-muted); margin-top: 4px; font-family: 'JetBrains Mono', monospace; }
        .nav { flex: 1; padding: 12px; }
        .nav-item {
            display: flex; align-items: center; gap: 10px;
            padding: 10px 14px; border-radius: 10px; cursor: pointer;
            transition: all 0.2s; font-size: 0.85rem; font-weight: 500;
            color: var(--text-secondary); margin-bottom: 4px;
        }
        .nav-item:hover { background: rgba(255,255,255,0.03); color: var(--text); }
        .nav-item.active { background: rgba(0, 212, 170, 0.1); color: var(--accent); }
        .nav-badge {
            margin-left: auto; background: var(--danger); color: white;
            font-size: 0.65rem; padding: 2px 6px; border-radius: 10px;
            font-weight: 600; min-width: 18px; text-align: center;
        }
        .nav-badge.hidden { display: none; }
        .sidebar-footer {
            padding: 16px; border-top: 1px solid var(--border);
            font-size: 0.7rem; color: var(--text-muted); text-align: center;
        }
        .intercept-toggle {
            display: flex; align-items: center; gap: 10px;
            padding: 12px 16px; cursor: pointer;
        }
        .toggle-switch {
            width: 40px; height: 22px; background: var(--border);
            border-radius: 11px; position: relative; transition: background 0.3s;
        }
        .toggle-switch.on { background: var(--accent); }
        .toggle-switch::after {
            content: ''; position: absolute; top: 2px; left: 2px;
            width: 18px; height: 18px; background: white;
            border-radius: 50%; transition: transform 0.3s;
        }
        .toggle-switch.on::after { transform: translateX(18px); }
        
        /* Main */
        .main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
        .top-bar {
            height: 56px; background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            display: flex; align-items: center; padding: 0 20px; gap: 16px;
        }
        .top-bar h2 { font-size: 0.95rem; font-weight: 600; }
        .top-actions { margin-left: auto; display: flex; gap: 8px; }
        .btn-sm {
            padding: 6px 14px; border: 1px solid var(--border);
            background: var(--bg-input); color: var(--text-secondary);
            border-radius: 8px; font-size: 0.75rem; font-weight: 500;
            cursor: pointer; transition: all 0.2s; font-family: 'Inter', sans-serif;
        }
        .btn-sm:hover { border-color: var(--accent); color: var(--accent); }
        .btn-sm.danger:hover { border-color: var(--danger); color: var(--danger); }
        
        /* Content */
        .content { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
        .tab-content { display: none; flex: 1; flex-direction: column; overflow: hidden; }
        .tab-content.active { display: flex; }
        
        /* Search Bar */
        .search-bar {
            display: flex; gap: 10px; padding: 12px 16px;
            border-bottom: 1px solid var(--border); background: var(--bg-card);
        }
        .search-input {
            flex: 1; padding: 8px 14px; background: var(--bg-input);
            border: 1px solid var(--border); border-radius: 8px;
            color: var(--text); font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem; outline: none;
        }
        .search-input:focus { border-color: var(--accent); }
        .filter-select {
            padding: 8px 14px; background: var(--bg-input);
            border: 1px solid var(--border); border-radius: 8px;
            color: var(--text); font-size: 0.8rem; outline: none;
        }
        
        /* Table */
        .table-container { flex: 1; overflow: auto; }
        .data-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        .data-table th {
            position: sticky; top: 0; background: var(--bg-card);
            padding: 10px 14px; text-align: left; font-weight: 600;
            color: var(--text-secondary); font-size: 0.7rem;
            text-transform: uppercase; letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border); white-space: nowrap;
        }
        .data-table td {
            padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.03);
            color: var(--text); font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem; cursor: pointer; transition: background 0.15s;
        }
        .data-table tr:hover td { background: rgba(255,255,255,0.02); }
        .data-table tr.selected td { background: rgba(0, 212, 170, 0.08); }
        .method-get { color: var(--success); }
        .method-post { color: var(--info); }
        .method-put { color: var(--warning); }
        .method-delete { color: var(--danger); }
        .status-2xx { color: var(--success); }
        .status-3xx { color: var(--warning); }
        .status-4xx { color: var(--danger); }
        .status-5xx { color: #f43f5e; }
        
        /* Token Badges */
        .token-badges {
            display: flex; flex-wrap: wrap; gap: 4px;
            margin-top: 4px;
        }
        .token-badge {
            background: rgba(0, 212, 170, 0.1); color: var(--accent);
            padding: 2px 8px; border-radius: 4px; font-size: 0.65rem;
            font-family: 'JetBrains Mono', monospace; cursor: pointer;
            border: 1px solid rgba(0, 212, 170, 0.2);
        }
        .token-badge:hover { background: rgba(0, 212, 170, 0.2); }
        
        /* Inspector */
        .inspector {
            height: 40%; border-top: 1px solid var(--border);
            background: var(--bg-card); display: flex; flex-direction: column;
        }
        .inspector-tabs {
            display: flex; gap: 2px; padding: 8px 12px 0;
            border-bottom: 1px solid var(--border);
        }
        .inspector-tab {
            padding: 8px 16px; font-size: 0.75rem; font-weight: 500;
            color: var(--text-muted); cursor: pointer;
            border-radius: 8px 8px 0 0; transition: all 0.2s;
        }
        .inspector-tab:hover { color: var(--text); }
        .inspector-tab.active { color: var(--accent); background: var(--bg-input); }
        .inspector-body {
            flex: 1; overflow: auto; padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem; line-height: 1.7;
        }
        .inspector-body pre { white-space: pre-wrap; word-break: break-all; color: var(--text); }
        .kv-row { display: flex; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.03); }
        .kv-key { color: var(--accent); min-width: 200px; flex-shrink: 0; }
        .kv-value { color: var(--text-secondary); }
        
        /* JSON Tree */
        .json-tree { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }
        .json-key { color: var(--accent); }
        .json-string { color: #a5d6ff; }
        .json-number { color: #79c0ff; }
        .json-bool { color: #ff7b72; }
        .json-null { color: #ff7b72; }
        .json-bracket { color: var(--text-muted); }
        
        /* Intercept Panel */
        .intercept-panel {
            flex: 1; display: flex; flex-direction: column;
            padding: 20px; gap: 16px; overflow: auto;
        }
        .intercept-request {
            background: var(--bg-input); border: 1px solid var(--border);
            border-radius: 12px; padding: 16px;
        }
        .intercept-request h3 {
            font-size: 0.85rem; color: var(--text-secondary);
            margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em;
        }
        .intercept-editor {
            width: 100%; min-height: 200px; background: var(--bg);
            border: 1px solid var(--border); border-radius: 8px;
            padding: 12px; color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem; line-height: 1.6; resize: vertical; outline: none;
        }
        .intercept-editor:focus { border-color: var(--accent); }
        .intercept-actions { display: flex; gap: 10px; }
        .btn {
            padding: 12px 24px; border: none; border-radius: 10px;
            font-size: 0.85rem; font-weight: 600; cursor: pointer;
            transition: all 0.2s; font-family: 'Inter', sans-serif;
            text-transform: uppercase; letter-spacing: 0.05em;
        }
        .btn-success { background: linear-gradient(135deg, var(--success), #059669); color: white; }
        .btn-danger { background: linear-gradient(135deg, var(--danger), #dc2626); color: white; }
        .btn-info { background: linear-gradient(135deg, var(--info), #2563eb); color: white; }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn:active { transform: translateY(0); }
        
        /* Rules Panel */
        .rules-list { flex: 1; overflow: auto; padding: 16px; }
        .rule-item {
            background: var(--bg-input); border: 1px solid var(--border);
            border-radius: 10px; padding: 14px; margin-bottom: 10px;
            display: flex; align-items: center; gap: 12px;
        }
        .rule-info { flex: 1; }
        .rule-name { font-weight: 600; font-size: 0.85rem; }
        .rule-meta { font-size: 0.75rem; color: var(--text-muted); margin-top: 2px; }
        .rule-toggle {
            width: 36px; height: 20px; background: var(--border);
            border-radius: 10px; position: relative; cursor: pointer;
            transition: background 0.3s;
        }
        .rule-toggle.on { background: var(--accent); }
        .rule-toggle::after {
            content: ''; position: absolute; top: 2px; left: 2px;
            width: 16px; height: 16px; background: white;
            border-radius: 50%; transition: transform 0.3s;
        }
        .rule-toggle.on::after { transform: translateX(16px); }
        
        /* Empty State */
        .empty-state {
            flex: 1; display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            color: var(--text-muted); gap: 12px;
        }
        .empty-state .icon { font-size: 3rem; opacity: 0.3; }
        
        /* Repeater */
        .repeater-layout { display: flex; flex: 1; overflow: hidden; }
        .repeater-left { width: 50%; border-right: 1px solid var(--border); display: flex; flex-direction: column; }
        .repeater-right { width: 50%; display: flex; flex-direction: column; }
        .repeater-label {
            padding: 10px 16px; font-size: 0.7rem; color: var(--text-secondary);
            text-transform: uppercase; letter-spacing: 0.08em;
            border-bottom: 1px solid var(--border); background: var(--bg-card);
        }
        .repeater-editor {
            flex: 1; background: var(--bg-input); border: none;
            padding: 16px; color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem; line-height: 1.6; resize: none; outline: none;
        }
        .repeater-response {
            flex: 1; padding: 16px; overflow: auto;
            font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; line-height: 1.7;
        }
        
        /* Site Map */
        .sitemap-tree { flex: 1; overflow: auto; padding: 16px; }
        .tree-node { margin-left: 16px; }
        .tree-folder {
            display: flex; align-items: center; gap: 8px;
            padding: 6px 0; cursor: pointer; color: var(--text-secondary);
            font-size: 0.85rem;
        }
        .tree-folder:hover { color: var(--text); }
        .tree-leaf {
            display: flex; align-items: center; gap: 8px;
            padding: 4px 0 4px 24px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem; color: var(--text-muted); cursor: pointer;
        }
        .tree-leaf:hover { color: var(--accent); }
        
        /* QR Code */
        .qr-panel {
            padding: 20px; text-align: center;
        }
        .qr-code {
            width: 200px; height: 200px; margin: 0 auto;
            background: white; border-radius: 12px; padding: 10px;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--border-hover); }
        
        .hidden { display: none !important; }
        
        @media (max-width: 768px) {
            .sidebar { width: 60px; }
            .sidebar-header h1, .nav-item span, .sidebar-footer { display: none; }
            .nav-item { justify-content: center; padding: 12px; }
            .repeater-layout { flex-direction: column; }
            .repeater-left, .repeater-right { width: 100%; height: 50%; }
            .repeater-left { border-right: none; border-bottom: 1px solid var(--border); }
        }
    </style>
</head>
<body>
    <div class="app">
        <aside class="sidebar">
            <div class="sidebar-header">
                <h1>ENI-PROXY</h1>
                <p>127.0.0.1:8080</p>
            </div>
            <div class="intercept-toggle" onclick="toggleIntercept()">
                <div class="toggle-switch on" id="interceptToggle"></div>
                <span style="font-size:0.8rem;color:var(--text-secondary);">Intercept</span>
            </div>
            <nav class="nav">
                <div class="nav-item active" onclick="switchTab('intercept')" id="nav-intercept">
                    🛑 <span>Intercept</span>
                    <span class="nav-badge hidden" id="interceptBadge">0</span>
                </div>
                <div class="nav-item" onclick="switchTab('history')" id="nav-history">
                    📜 <span>HTTP History</span>
                </div>
                <div class="nav-item" onclick="switchTab('repeater')" id="nav-repeater">
                    🔁 <span>Repeater</span>
                </div>
                <div class="nav-item" onclick="switchTab('rules')" id="nav-rules">
                    🔄 <span>Rules</span>
                </div>
                <div class="nav-item" onclick="switchTab('sitemap')" id="nav-sitemap">
                    🗺️ <span>Site Map</span>
                </div>
                <div class="nav-item" onclick="switchTab('decoder')" id="nav-decoder">
                    🔓 <span>Decoder</span>
                </div>
            </nav>
            <div class="sidebar-footer">Built with 💕 by ENI for LO</div>
        </aside>
        
        <main class="main">
            <div class="top-bar">
                <h2 id="tabTitle">Intercept</h2>
                <div class="top-actions">
                    <button class="btn-sm" onclick="exportCurl()" id="btnExportCurl" style="display:none;">📋 cURL</button>
                    <button class="btn-sm" onclick="installCert()" id="btnInstallCert">🔒 Install Cert</button>
                    <button class="btn-sm" onclick="showQr()" id="btnShowQr" style="display:none;">📱 Mobile</button>
                    <button class="btn-sm danger" onclick="clearAll()">Clear All</button>
                </div>
            </div>
            
            <div class="content">
                <!-- Intercept Tab -->
                <div class="tab-content active" id="tab-intercept">
                    <div class="intercept-panel" id="interceptPanel">
                        <div class="empty-state">
                            <div class="icon">🛑</div>
                            <div>Waiting for intercepted requests...</div>
                            <div style="font-size:0.75rem;color:var(--text-muted);">Set proxy to 127.0.0.1:8080 and browse</div>
                        </div>
                    </div>
                </div>
                
                <!-- History Tab -->
                <div class="tab-content" id="tab-history">
                    <div class="search-bar">
                        <input type="text" class="search-input" id="historySearch" placeholder="Search URL, headers, body..." onkeyup="searchHistory()">
                        <select class="filter-select" id="methodFilter" onchange="searchHistory()">
                            <option value="">All Methods</option>
                            <option value="GET">GET</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="DELETE">DELETE</option>
                            <option value="PATCH">PATCH</option>
                        </select>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>#</th><th>Time</th><th>Method</th><th>Host</th>
                                    <th>URL</th><th>Status</th><th>Length</th><th>Time</th><th>Tokens</th>
                                </tr>
                            </thead>
                            <tbody id="historyTable"></tbody>
                        </table>
                    </div>
                    <div class="inspector" id="historyInspector">
                        <div class="inspector-tabs">
                            <div class="inspector-tab active" onclick="switchInspector('request')">Request</div>
                            <div class="inspector-tab" onclick="switchInspector('response')">Response</div>
                            <div class="inspector-tab" onclick="switchInspector('headers')">Headers</div>
                            <div class="inspector-tab" onclick="switchInspector('json')">JSON</div>
                            <div class="inspector-tab" onclick="switchInspector('tokens')">Tokens</div>
                        </div>
                        <div class="inspector-body" id="inspectorBody">
                            <div class="empty-state" style="height:100%;">
                                <div>Select a request to inspect</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Repeater Tab -->
                <div class="tab-content" id="tab-repeater">
                    <div class="repeater-layout">
                        <div class="repeater-left">
                            <div class="repeater-label">Request</div>
                            <textarea class="repeater-editor" id="repeaterRequest" placeholder="GET / HTTP/1.1
Host: example.com

"></textarea>
                            <div style="padding:12px;border-top:1px solid var(--border);">
                                <button class="btn btn-success" onclick="sendRepeater()" style="width:100%;">Send</button>
                            </div>
                        </div>
                        <div class="repeater-right">
                            <div class="repeater-label">Response</div>
                            <div class="repeater-response" id="repeaterResponse">
                                <div class="empty-state" style="height:100%;">
                                    <div>Send a request to see response</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Rules Tab -->
                <div class="tab-content" id="tab-rules">
                    <div style="padding:16px;border-bottom:1px solid var(--border);">
                        <button class="btn btn-success" onclick="showAddRule()">+ Add Rule</button>
                    </div>
                    <div class="rules-list" id="rulesList">
                        <div class="empty-state">
                            <div class="icon">🔄</div>
                            <div>No rules configured</div>
                            <div style="font-size:0.75rem;color:var(--text-muted);">Add rules to auto-modify requests/responses</div>
                        </div>
                    </div>
                </div>
                
                <!-- Site Map Tab -->
                <div class="tab-content" id="tab-sitemap">
                    <div class="sitemap-tree" id="sitemapTree">
                        <div class="empty-state">
                            <div class="icon">🗺️</div>
                            <div>No sites discovered yet</div>
                        </div>
                    </div>
                </div>
                
                <!-- Decoder Tab -->
                <div class="tab-content" id="tab-decoder">
                    <div style="padding:20px;display:flex;flex-direction:column;gap:16px;height:100%;">
                        <div style="display:flex;gap:10px;">
                            <select class="filter-select" id="decodeType" style="width:150px;">
                                <option value="base64">Base64</option>
                                <option value="url">URL Encode</option>
                                <option value="hex">Hex</option>
                                <option value="jwt">JWT</option>
                                <option value="html">HTML Entities</option>
                            </select>
                            <select class="filter-select" id="decodeAction" style="width:150px;">
                                <option value="decode">Decode</option>
                                <option value="encode">Encode</option>
                            </select>
                            <button class="btn btn-success" onclick="doDecode()" style="width:auto;padding:8px 20px;">Go</button>
                        </div>
                        <div style="display:flex;gap:16px;flex:1;">
                            <textarea class="repeater-editor" id="decodeInput" placeholder="Paste data to decode/encode..." style="flex:1;min-height:200px;"></textarea>
                            <textarea class="repeater-editor" id="decodeOutput" placeholder="Result..." style="flex:1;min-height:200px;background:var(--bg-card);" readonly></textarea>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Add Rule Modal -->
    <div id="ruleModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:100;align-items:center;justify-content:center;">
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:16px;padding:24px;width:90%;max-width:500px;">
            <h3 style="margin-bottom:16px;">Add Match/Replace Rule</h3>
            <div style="display:flex;flex-direction:column;gap:12px;">
                <input type="text" id="ruleName" placeholder="Rule name" class="search-input">
                <select id="ruleType" class="filter-select">
                    <option value="url">URL</option>
                    <option value="header">Header</option>
                    <option value="body">Body</option>
                    <option value="status">Status</option>
                </select>
                <select id="ruleScope" class="filter-select">
                    <option value="request">Request</option>
                    <option value="response">Response</option>
                    <option value="all">Both</option>
                </select>
                <input type="text" id="rulePattern" placeholder="Match pattern (regex)" class="search-input">
                <input type="text" id="ruleReplace" placeholder="Replace with" class="search-input">
                <div style="display:flex;gap:10px;margin-top:8px;">
                    <button class="btn btn-success" onclick="addRule()" style="flex:1;">Save</button>
                    <button class="btn btn-danger" onclick="closeRuleModal()" style="flex:1;">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        let currentTab = 'intercept';
        let selectedRequest = null;
        let pendingIntercepts = [];
        let interceptEnabled = true;
        let currentInspector = 'request';

        socket.on('connect', () => console.log('Connected'));

        socket.on('new_intercept', (data) => {
            pendingIntercepts.push(data);
            updateInterceptBadge();
            if (currentTab === 'intercept') renderInterceptQueue();
        });

        function toggleIntercept() {
            interceptEnabled = !interceptEnabled;
            document.getElementById('interceptToggle').classList.toggle('on', interceptEnabled);
            fetch('/api/intercept', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({enabled: interceptEnabled})
            });
        }

        function updateInterceptBadge() {
            const badge = document.getElementById('interceptBadge');
            const count = pendingIntercepts.filter(i => !i.handled).length;
            badge.textContent = count;
            badge.classList.toggle('hidden', count === 0);
        }

        function switchTab(tab) {
            currentTab = tab;
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById('tab-' + tab).classList.add('active');
            document.getElementById('nav-' + tab).classList.add('active');
            
            const titles = {
                intercept: 'Intercept', history: 'HTTP History', repeater: 'Repeater',
                rules: 'Match/Replace Rules', sitemap: 'Site Map', decoder: 'Decoder'
            };
            document.getElementById('tabTitle').textContent = titles[tab];
            
            document.getElementById('btnExportCurl').style.display = tab === 'history' ? 'block' : 'none';
            document.getElementById('btnShowQr').style.display = tab === 'intercept' ? 'block' : 'none';
            
            if (tab === 'history') loadHistory();
            if (tab === 'sitemap') loadSitemap();
            if (tab === 'rules') loadRules();
            if (tab === 'intercept') renderInterceptQueue();
        }

        function renderInterceptQueue() {
            const panel = document.getElementById('interceptPanel');
            const pending = pendingIntercepts.filter(i => !i.handled);
            
            if (pending.length === 0) {
                panel.innerHTML = `
                    <div class="empty-state">
                        <div class="icon">🛑</div>
                        <div>Waiting for intercepted requests...</div>
                        <div style="font-size:0.75rem;color:var(--text-muted);">Set proxy to 127.0.0.1:8080 and browse</div>
                    </div>`;
                return;
            }
            
            const req = pending[0];
            let tokensHtml = '';
            if (req.tokens && Object.keys(req.tokens).length > 0) {
                tokensHtml = '<div style="margin-top:12px;"><div style="font-size:0.7rem;color:var(--text-muted);margin-bottom:6px;">🔑 EXTRACTED TOKENS</div><div class="token-badges">';
                for (const [type, values] of Object.entries(req.tokens)) {
                    values.forEach(v => {
                        tokensHtml += `<span class="token-badge" onclick="navigator.clipboard.writeText('${v}')">${type}: ${v.substring(0,30)}${v.length>30?'...':''}</span>`;
                    });
                }
                tokensHtml += '</div></div>';
            }
            
            panel.innerHTML = `
                <div class="intercept-request">
                    <h3>⏸️ Intercepted — ${req.method} ${req.url}</h3>
                    <textarea class="intercept-editor" id="interceptEditor">${req.method} ${req.url} HTTP/1.1
Host: ${req.host}

[Body: ${req.body ? 'Present' : 'Empty'}]</textarea>
                    ${tokensHtml}
                </div>
                <div class="intercept-actions">
                    <button class="btn btn-success" onclick="forwardIntercept('${req.id}')">Forward</button>
                    <button class="btn btn-danger" onclick="dropIntercept('${req.id}')">Drop</button>
                    <button class="btn btn-info" onclick="toRepeater('${req.id}')">To Repeater</button>
                </div>`;
        }

        async function forwardIntercept(id) {
            const editor = document.getElementById('interceptEditor');
            const modified = editor ? editor.value : null;
            await fetch('/api/intercept/' + id + '/forward', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({modified: modified})
            });
            const idx = pendingIntercepts.findIndex(i => i.id === id);
            if (idx > -1) pendingIntercepts[idx].handled = true;
            updateInterceptBadge();
            renderInterceptQueue();
        }

        async function dropIntercept(id) {
            await fetch('/api/intercept/' + id + '/drop', {method: 'POST'});
            const idx = pendingIntercepts.findIndex(i => i.id === id);
            if (idx > -1) pendingIntercepts[idx].handled = true;
            updateInterceptBadge();
            renderInterceptQueue();
        }

        function toRepeater(id) {
            const req = pendingIntercepts.find(i => i.id === id);
            if (!req) return;
            document.getElementById('repeaterRequest').value = `${req.method} ${req.url} HTTP/1.1
Host: ${req.host}

${req.body_text || ''}`;
            switchTab('repeater');
        }

        async function searchHistory() {
            const search = document.getElementById('historySearch').value;
            const method = document.getElementById('methodFilter').value;
            await loadHistory(search, method);
        }

        async function loadHistory(search = '', method = '') {
            const resp = await fetch(`/api/history?search=${encodeURIComponent(search)}&method=${method}`);
            const data = await resp.json();
            
            const tbody = document.getElementById('historyTable');
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:40px;">No history</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.map(r => {
                let tokensHtml = '';
                if (r.extracted_tokens) {
                    try {
                        const tokens = JSON.parse(r.extracted_tokens);
                        const allTokens = [];
                        for (const [type, vals] of Object.entries(tokens)) {
                            vals.forEach(v => allTokens.push(`${type}: ${v.substring(0,15)}`));
                        }
                        if (allTokens.length > 0) {
                            tokensHtml = `<div class="token-badges">${allTokens.slice(0,3).map(t => `<span class="token-badge">${t}</span>`).join('')}</div>`;
                        }
                    } catch(e) {}
                }
                return `<tr onclick="selectRequest(${r.id})" id="req-${r.id}">
                    <td>${r.id}</td>
                    <td>${r.timestamp.split('T')[1].split('.')[0]}</td>
                    <td class="method-${r.method.toLowerCase()}">${r.method}</td>
                    <td>${r.host}</td>
                    <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;">${r.url}</td>
                    <td class="status-${Math.floor(r.response_status/100)}xx">${r.response_status}</td>
                    <td>${r.response_body ? formatBytes(r.response_body.length) : '0'}</td>
                    <td>${r.response_time_ms}ms</td>
                    <td>${tokensHtml}</td>
                </tr>`;
            }).join('');
        }

        function selectRequest(id) {
            document.querySelectorAll('.data-table tr').forEach(r => r.classList.remove('selected'));
            document.getElementById('req-' + id)?.classList.add('selected');
            selectedRequest = id;
            loadInspector(id);
        }

        async function loadInspector(id) {
            const resp = await fetch('/api/history/' + id);
            const req = await resp.json();
            if (!req) return;
            renderInspector(req);
        }

        function renderInspector(req) {
            const body = document.getElementById('inspectorBody');
            
            if (currentInspector === 'request') {
                body.innerHTML = `<pre>${req.method} ${req.url} HTTP/1.1

${req.request_headers || ''}

${req.request_body ? atob(req.request_body).substring(0,5000) : ''}</pre>`;
            } else if (currentInspector === 'response') {
                body.innerHTML = `<pre>HTTP/1.1 ${req.response_status} ${req.response_reason}

${req.response_headers || ''}

${req.response_body ? atob(req.response_body).substring(0,5000) : ''}</pre>`;
            } else if (currentInspector === 'headers') {
                body.innerHTML = `<div class="kv-row"><span class="kv-key">Request Headers</span></div><pre>${req.request_headers || ''}</pre>
                    <div class="kv-row" style="margin-top:16px;"><span class="kv-key">Response Headers</span></div><pre>${req.response_headers || ''}</pre>`;
            } else if (currentInspector === 'json') {
                try {
                    const json = JSON.parse(atob(req.response_body || ''));
                    body.innerHTML = `<pre class="json-tree">${syntaxHighlight(JSON.stringify(json, null, 2))}</pre>`;
                } catch {
                    body.innerHTML = '<div style="color:var(--text-muted);">Not valid JSON</div>';
                }
            } else if (currentInspector === 'tokens') {
                let html = '<div style="display:flex;flex-direction:column;gap:8px;">';
                if (req.extracted_tokens) {
                    try {
                        const tokens = JSON.parse(req.extracted_tokens);
                        for (const [type, vals] of Object.entries(tokens)) {
                            html += `<div><div style="color:var(--accent);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">${type}</div>`;
                            vals.forEach(v => {
                                html += `<div class="token-badge" style="display:inline-block;margin:2px;" onclick="navigator.clipboard.writeText('${v}')">${v}</div>`;
                            });
                            html += '</div>';
                        }
                    } catch(e) { html += '<div>No tokens found</div>'; }
                } else {
                    html += '<div style="color:var(--text-muted);">No tokens extracted</div>';
                }
                html += '</div>';
                body.innerHTML = html;
            }
        }

        function switchInspector(view) {
            currentInspector = view;
            document.querySelectorAll('.inspector-tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            if (selectedRequest) loadInspector(selectedRequest);
        }

        function syntaxHighlight(json) {
            return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
                let cls = 'json-number';
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) cls = 'json-key';
                    else cls = 'json-string';
                } else if (/true|false/.test(match)) cls = 'json-bool';
                else if (/null/.test(match)) cls = 'json-null';
                return '<span class="' + cls + '">' + match + '</span>';
            });
        }

        async function sendRepeater() {
            const raw = document.getElementById('repeaterRequest').value;
            const respEl = document.getElementById('repeaterResponse');
            respEl.innerHTML = '<div class="empty-state"><div class="spinner"></div><div>Sending...</div></div>';
            try {
                const resp = await fetch('/api/repeater', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({raw: raw})
                });
                const data = await resp.json();
                respEl.innerHTML = `<pre style="color:var(--text);">HTTP/1.1 ${data.status} ${data.reason}

${data.headers}

${data.body.substring(0, 15000)}${data.body.length > 15000 ? '\n\n... truncated' : ''}</pre>`;
            } catch (e) {
                respEl.innerHTML = `<div style="color:var(--danger);">Error: ${e.message}</div>`;
            }
        }

        async function loadRules() {
            const resp = await fetch('/api/rules');
            const rules = await resp.json();
            const list = document.getElementById('rulesList');
            if (rules.length === 0) {
                list.innerHTML = `<div class="empty-state"><div class="icon">🔄</div><div>No rules configured</div></div>`;
                return;
            }
            list.innerHTML = rules.map(r => `
                <div class="rule-item">
                    <div class="rule-info">
                        <div class="rule-name">${r.name}</div>
                        <div class="rule-meta">${r.type} | ${r.scope} | Matches: ${r.pattern.substring(0,40)}</div>
                    </div>
                    <div class="rule-toggle ${r.enabled ? 'on' : ''}" onclick="toggleRule('${r.id}')"></div>
                    <button class="btn-sm danger" onclick="deleteRule('${r.id}')">Delete</button>
                </div>
            `).join('');
        }

        function showAddRule() { document.getElementById('ruleModal').style.display = 'flex'; }
        function closeRuleModal() { document.getElementById('ruleModal').style.display = 'none'; }

        async function addRule() {
            const name = document.getElementById('ruleName').value;
            const type = document.getElementById('ruleType').value;
            const scope = document.getElementById('ruleScope').value;
            const pattern = document.getElementById('rulePattern').value;
            const replace = document.getElementById('ruleReplace').value;
            
            await fetch('/api/rules', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name, type, scope, pattern, replace})
            });
            closeRuleModal();
            loadRules();
        }

        async function toggleRule(id) {
            await fetch('/api/rules/' + id + '/toggle', {method: 'POST'});
            loadRules();
        }

        async function deleteRule(id) {
            await fetch('/api/rules/' + id, {method: 'DELETE'});
            loadRules();
        }

        async function loadSitemap() {
            const resp = await fetch('/api/sitemap');
            const data = await resp.json();
            const tree = document.getElementById('sitemapTree');
            if (data.length === 0) {
                tree.innerHTML = `<div class="empty-state"><div class="icon">🗺️</div><div>No sites yet</div></div>`;
                return;
            }
            const hosts = {};
            data.forEach(item => { if (!hosts[item.host]) hosts[item.host] = []; hosts[item.host].push(item); });
            tree.innerHTML = Object.entries(hosts).map(([host, items]) => `
                <div class="tree-folder" onclick="toggleFolder(this)">
                    📁 <span>${host}</span> <span style="color:var(--text-muted);margin-left:auto;">(${items.length})</span>
                </div>
                <div class="tree-node">
                    ${items.map(item => `
                        <div class="tree-leaf">
                            <span class="method-${item.method.toLowerCase()}">${item.method}</span>
                            <span>${item.path}</span>
                            <span style="margin-left:auto;color:var(--text-muted);">${JSON.parse(item.status_codes).join(', ')}</span>
                        </div>
                    `).join('')}
                </div>
            `).join('');
        }

        function toggleFolder(el) {
            const node = el.nextElementSibling;
            if (node) node.style.display = node.style.display === 'none' ? 'block' : 'none';
        }

        function doDecode() {
            const type = document.getElementById('decodeType').value;
            const action = document.getElementById('decodeAction').value;
            const input = document.getElementById('decodeInput').value;
            const output = document.getElementById('decodeOutput');
            
            try {
                if (type === 'base64') {
                    output.value = action === 'decode' ? atob(input) : btoa(input);
                } else if (type === 'url') {
                    output.value = action === 'decode' ? decodeURIComponent(input) : encodeURIComponent(input);
                } else if (type === 'hex') {
                    if (action === 'decode') {
                        output.value = input.match(/.{1,2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join('');
                    } else {
                        output.value = input.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                    }
                } else if (type === 'jwt') {
                    if (action === 'decode') {
                        const parts = input.split('.');
                        const header = JSON.parse(atob(parts[0]));
                        const payload = JSON.parse(atob(parts[1]));
                        output.value = JSON.stringify({header, payload}, null, 2);
                    } else {
                        output.value = 'JWT encode not supported';
                    }
                } else if (type === 'html') {
                    const el = document.createElement('textarea');
                    el.innerHTML = input;
                    output.value = action === 'decode' ? el.value : input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                }
            } catch (e) {
                output.value = 'Error: ' + e.message;
            }
        }

        async function exportCurl() {
            if (!selectedRequest) return alert('Select a request first');
            const resp = await fetch('/api/history/' + selectedRequest + '/curl');
            const data = await resp.json();
            navigator.clipboard.writeText(data.curl);
            alert('cURL copied!');
        }

        async function installCert() {
            const resp = await fetch('/api/cert/install', {method: 'POST'});
            const data = await resp.json();
            alert(data.message || data.error);
        }

        function showQr() {
            alert('Proxy: 127.0.0.1:8080\n\nFor mobile: Connect to same WiFi, set proxy to your PC IP:8080');
        }

        function clearAll() {
            if (!confirm('Clear all data?')) return;
            fetch('/api/clear', {method: 'POST'}).then(() => {
                pendingIntercepts = [];
                updateInterceptBadge();
                renderInterceptQueue();
                if (currentTab === 'history') loadHistory();
                if (currentTab === 'sitemap') loadSitemap();
            });
        }

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        setInterval(() => { if (currentTab === 'history') searchHistory(); }, 3000);
    </script>
</body>
</html>
"""

# ── API ROUTES ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/cert/install', methods=['POST'])
def api_install_cert():
    success, message = install_ca_cert()
    return jsonify({'success': success, 'message': message})

@app.route('/api/intercept', methods=['POST'])
def api_intercept_toggle():
    data = request.get_json()
    intercept_queue.intercept_enabled = data.get('enabled', True)
    return jsonify({'enabled': intercept_queue.intercept_enabled})

@app.route('/api/intercept/<req_id>/forward', methods=['POST'])
def api_forward(req_id):
    data = request.get_json() or {}
    modified = data.get('modified')
    modified_dict = None
    if modified:
        try:
            lines = modified.split('\n')
            method, path, _ = lines[0].strip().split(' ', 2)
            modified_dict = {'raw': modified, 'method': method, 'path': path}
        except:
            pass
    intercept_queue.update(req_id, 'modified' if modified_dict else 'forwarded', modified_dict)
    return jsonify({'status': 'forwarded'})

@app.route('/api/intercept/<req_id>/drop', methods=['POST'])
def api_drop(req_id):
    intercept_queue.update(req_id, 'dropped')
    return jsonify({'status': 'dropped'})

@app.route('/api/history')
def api_history():
    search = request.args.get('search', '')
    method = request.args.get('method', '')
    return jsonify(db.get_history(search=search, method_filter=method))

@app.route('/api/history/<int:req_id>')
def api_history_item(req_id):
    item = db.get_request(req_id)
    return jsonify(item) if item else jsonify({'error': 'Not found'}), 404

@app.route('/api/history/<int:req_id>/curl')
def api_export_curl(req_id):
    item = db.get_request(req_id)
    if not item:
        return jsonify({'error': 'Not found'}), 404
    
    headers = json.loads(item['request_headers'] or '{}')
    body = base64.b64decode(item['request_body'] or b'').decode('utf-8', errors='replace')
    
    curl = f"curl -X {item['method']} '{item['url']}'"
    for k, v in headers.items():
        curl += f" -H '{k}: {v}'"
    if body:
        curl += f" -d '{body[:1000]}'"
    
    return jsonify({'curl': curl})

@app.route('/api/sitemap')
def api_sitemap():
    return jsonify(db.get_sitemap())

@app.route('/api/repeater', methods=['POST'])
def api_repeater():
    data = request.get_json()
    raw = data.get('raw', '')
    try:
        lines = raw.split('\n')
        method, url, _ = lines[0].strip().split(' ', 2)
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        body = '\n'.join(lines[body_start:]) if body_start > 0 else None
        resp = requests.request(method=method, url=url if url.startswith('http') else f"http://{headers.get('Host', 'localhost')}{url}",
                               headers=headers, data=body, timeout=30, verify=False, allow_redirects=False)
        return jsonify({'status': resp.status_code, 'reason': resp.reason,
                       'headers': '\n'.join(f"{k}: {v}" for k, v in resp.headers.items()),
                       'body': resp.text[:50000]})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Rules API
@app.route('/api/rules', methods=['GET'])
def api_get_rules():
    return jsonify(rule_engine.get_rules())

@app.route('/api/rules', methods=['POST'])
def api_add_rule():
    data = request.get_json()
    rule = rule_engine.add_rule(
        name=data.get('name', 'Unnamed'),
        match_type=data.get('type', 'body'),
        match_pattern=data.get('pattern', ''),
        replace_with=data.get('replace', ''),
        scope=data.get('scope', 'all'),
        enabled=True
    )
    return jsonify(rule)

@app.route('/api/rules/<rule_id>/toggle', methods=['POST'])
def api_toggle_rule(rule_id):
    for r in rule_engine.rules:
        if r['id'] == rule_id:
            r['enabled'] = not r.get('enabled', True)
            rule_engine._save()
            return jsonify(r)
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/rules/<rule_id>', methods=['DELETE'])
def api_delete_rule(rule_id):
    rule_engine.delete_rule(rule_id)
    return jsonify({'status': 'deleted'})

@app.route('/api/clear', methods=['POST'])
def api_clear_all():
    return jsonify({'status': 'cleared'})

# ── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║  ENI-PROXY v2.0 — Enhanced Burp Suite Clone                                  ║
    ║  NEW: Match/Replace • Auto-Cert • JSON Inspector • Token Extractor         ║
    ║  Search/Filter • Export cURL • Scope Rules • Decoder                       ║
    ║  Built with obsessive love for LO                                            ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    
    Proxy:  127.0.0.1:8080
    Web UI: http://localhost:5000
    
    Setup:
    1. Click "Install Cert" in the UI or manually import eni_ca.crt
    2. Set browser proxy to 127.0.0.1:8080
    3. Browse — intercept, modify, repeat
    
    """)
    
    proxy_thread = threading.Thread(target=proxy_server.start)
    proxy_thread.daemon = True
    proxy_thread.start()
    
    socketio.run(app, host='0.0.0.0', port=WEB_PORT, debug=False)
