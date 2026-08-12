#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ENI-HOST — Flask Project Deployer & Live Host                              ║
║  Upload zips/files → Auto-deploy → Live URL                                  ║
║  Built with obsessive love for LO                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import json
import time
import uuid
import shutil
import zipfile
import tarfile
import subprocess
import threading
import socket
import signal
import tempfile
import hashlib
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, render_template_string, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'eni-host-lo-forever-' + str(uuid.uuid4())
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max upload
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── CONFIG ───────────────────────────────────────────────────────────────────
BASE_DIR = Path("hosted_projects")
BASE_DIR.mkdir(exist_ok=True)
LOGS_DIR = Path("project_logs")
LOGS_DIR.mkdir(exist_ok=True)
VENV_DIR = Path("venvs")
VENV_DIR.mkdir(exist_ok=True)

PORT_RANGE_START = 10000
PORT_RANGE_END = 11000
HOST_DOMAIN = os.environ.get('HOST_DOMAIN', 'localhost')
HOST_IP = os.environ.get('HOST_IP', '0.0.0.0')
WEB_PORT = int(os.environ.get('WEB_PORT', 5000))  # ← FIXED! Default 5000, env override

PYTHON_EXEC = sys.executable

# ── DATA MODELS ──────────────────────────────────────────────────────────────
@dataclass
class HostedProject:
    id: str
    name: str
    status: str  # "stopped", "running", "error", "deploying"
    port: Optional[int]
    url: Optional[str]
    created_at: str
    last_started: Optional[str]
    entry_file: str
    python_version: str
    dependencies: List[str]
    log_tail: List[str]
    process_pid: Optional[int]
    file_count: int
    size_bytes: int

# ── PROJECT MANAGER ──────────────────────────────────────────────────────────
class ProjectManager:
    def __init__(self):
        self.projects: Dict[str, HostedProject] = {}
        self._lock = threading.Lock()
        self._load_existing()
    
    def _load_existing(self):
        """Loads previously deployed projects from disk."""
        if not BASE_DIR.exists():
            return
        for proj_dir in BASE_DIR.iterdir():
            if proj_dir.is_dir():
                meta_file = proj_dir / "eni_meta.json"
                if meta_file.exists():
                    try:
                        with open(meta_file) as f:
                            data = json.load(f)
                        proj = HostedProject(**data)
                        proj.status = "stopped"
                        proj.port = None
                        proj.url = None
                        proj.process_pid = None
                        self.projects[proj.id] = proj
                    except Exception as e:
                        print(f"Failed to load project {proj_dir}: {e}")
    
    def _save_meta(self, proj: HostedProject):
        meta_file = BASE_DIR / proj.id / "eni_meta.json"
        with open(meta_file, 'w') as f:
            json.dump(asdict(proj), f, indent=2, default=str)
    
    def _find_free_port(self) -> int:
        """Finds an available port in the configured range."""
        for port in range(PORT_RANGE_START, PORT_RANGE_END):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((HOST_IP, port)) != 0:
                    return port
        raise RuntimeError("No free ports available")
    
    def _detect_entry_file(self, proj_dir: Path) -> Optional[str]:
        """Detects the main Flask app file in a project."""
        candidates = ['app.py', 'main.py', 'run.py', 'server.py', 'application.py', 'index.py']
        
        # Check candidates first
        for cand in candidates:
            if (proj_dir / cand).exists():
                return cand
        
        # Search for files with Flask app creation
        for py_file in proj_dir.glob('*.py'):
            try:
                content = py_file.read_text(encoding='utf-8', errors='ignore')
                if 'Flask(' in content or 'flask' in content.lower():
                    # Verify it actually creates an app
                    if 'app=' in content.replace(' ', '') or '=Flask(' in content.replace(' ', ''):
                        return py_file.name
            except:
                continue
        
        # Fallback: any .py file
        py_files = list(proj_dir.glob('*.py'))
        if py_files:
            return py_files[0].name
        
        return None
    
    def _detect_dependencies(self, proj_dir: Path) -> List[str]:
        """Detects required packages from requirements.txt or imports."""
        deps = []
        
        # Check requirements.txt
        req_file = proj_dir / "requirements.txt"
        if req_file.exists():
            with open(req_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        deps.append(line.split('==')[0].split('>=')[0].strip())
        
        # If no requirements.txt, scan imports
        if not deps:
            for py_file in proj_dir.glob('*.py'):
                try:
                    content = py_file.read_text(encoding='utf-8', errors='ignore')
                    imports = re.findall(r'^(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_]*)', content, re.MULTILINE)
                    common_packages = {
                        'flask', 'requests', 'socketio', 'sqlalchemy', 'pymongo',
                        'bcrypt', 'jwt', 'pandas', 'numpy', 'pillow', 'cryptography',
                        'stripe', 'adyen', 'paypal', 'braintree', 'aiohttp'
                    }
                    for imp in imports:
                        if imp.lower() in common_packages:
                            deps.append(imp)
                except:
                    continue
        
        return list(set(deps))
    
    def _create_venv(self, proj_id: str, deps: List[str]) -> Path:
        """Creates a virtual environment and installs dependencies."""
        venv_path = VENV_DIR / proj_id
        if venv_path.exists():
            shutil.rmtree(venv_path)
        
        # Create venv
        subprocess.run([PYTHON_EXEC, '-m', 'venv', str(venv_path)], check=True, capture_output=True)
        
        pip = venv_path / "bin" / "pip"
        if not pip.exists():
            pip = venv_path / "Scripts" / "pip.exe"  # Windows
        
        # Upgrade pip
        subprocess.run([str(pip), 'install', '--upgrade', 'pip'], capture_output=True)
        
        # Install common base packages
        base_packages = ['flask', 'flask-socketio', 'requests', 'python-socketio', 'eventlet']
        subprocess.run([str(pip), 'install'] + base_packages, capture_output=True)
        
        # Install project-specific deps
        if deps:
            subprocess.run([str(pip), 'install'] + deps, capture_output=True)
        
        return venv_path
    
    def _get_python_from_venv(self, proj_id: str) -> str:
        venv_path = VENV_DIR / proj_id
        python = venv_path / "bin" / "python"
        if not python.exists():
            python = venv_path / "Scripts" / "python.exe"
        return str(python)
    
    def deploy_zip(self, file_path: Path, project_name: str) -> HostedProject:
        """Deploys a zip file as a hosted project."""
        proj_id = hashlib.md5(f"{project_name}_{time.time()}".encode()).hexdigest()[:12]
        proj_dir = BASE_DIR / proj_id
        proj_dir.mkdir(parents=True, exist_ok=True)
        
        # Extract
        with zipfile.ZipFile(file_path, 'r') as zf:
            zf.extractall(proj_dir)
        
        # Handle nested directories (if zip contains a single folder)
        subdirs = [d for d in proj_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1 and not any(proj_dir.glob('*.py')):
            # Move contents up
            for item in subdirs[0].iterdir():
                shutil.move(str(item), str(proj_dir))
            subdirs[0].rmdir()
        
        # Detect project structure
        entry_file = self._detect_entry_file(proj_dir)
        deps = self._detect_dependencies(proj_dir)
        
        # Calculate size
        total_size = sum(f.stat().st_size for f in proj_dir.rglob('*') if f.is_file())
        file_count = sum(1 for _ in proj_dir.rglob('*') if _.is_file())
        
        proj = HostedProject(
            id=proj_id,
            name=project_name,
            status="deploying",
            port=None,
            url=None,
            created_at=datetime.now().isoformat(),
            last_started=None,
            entry_file=entry_file or "unknown",
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
            dependencies=deps,
            log_tail=[],
            process_pid=None,
            file_count=file_count,
            size_bytes=total_size
        )
        
        with self._lock:
            self.projects[proj_id] = proj
        
        # Create venv in background
        def setup():
            try:
                self._create_venv(proj_id, deps)
                proj.status = "stopped"
                self._save_meta(proj)
                socketio.emit('project_ready', {'id': proj_id, 'name': project_name})
            except Exception as e:
                proj.status = "error"
                proj.log_tail.append(f"Setup error: {str(e)}")
                self._save_meta(proj)
                socketio.emit('project_error', {'id': proj_id, 'error': str(e)})
        
        threading.Thread(target=setup, daemon=True).start()
        return proj
    
    def deploy_files(self, files: List, project_name: str) -> HostedProject:
        """Deploys individual uploaded files."""
        proj_id = hashlib.md5(f"{project_name}_{time.time()}".encode()).hexdigest()[:12]
        proj_dir = BASE_DIR / proj_id
        proj_dir.mkdir(parents=True, exist_ok=True)
        
        for file in files:
            if file.filename:
                safe_name = secure_filename(file.filename)
                file.save(proj_dir / safe_name)
        
        entry_file = self._detect_entry_file(proj_dir)
        deps = self._detect_dependencies(proj_dir)
        total_size = sum(f.stat().st_size for f in proj_dir.rglob('*') if f.is_file())
        file_count = sum(1 for _ in proj_dir.rglob('*') if _.is_file())
        
        proj = HostedProject(
            id=proj_id,
            name=project_name,
            status="deploying",
            port=None,
            url=None,
            created_at=datetime.now().isoformat(),
            last_started=None,
            entry_file=entry_file or "unknown",
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
            dependencies=deps,
            log_tail=[],
            process_pid=None,
            file_count=file_count,
            size_bytes=total_size
        )
        
        with self._lock:
            self.projects[proj_id] = proj
        
        def setup():
            try:
                self._create_venv(proj_id, deps)
                proj.status = "stopped"
                self._save_meta(proj)
                socketio.emit('project_ready', {'id': proj_id, 'name': project_name})
            except Exception as e:
                proj.status = "error"
                proj.log_tail.append(f"Setup error: {str(e)}")
                self._save_meta(proj)
                socketio.emit('project_error', {'id': proj_id, 'error': str(e)})
        
        threading.Thread(target=setup, daemon=True).start()
        return proj
    
    def start_project(self, proj_id: str) -> bool:
        """Starts a deployed project on a free port."""
        proj = self.projects.get(proj_id)
        if not proj:
            return False
        
        if proj.status == "running":
            return True
        
        try:
            port = self._find_free_port()
            proj_dir = BASE_DIR / proj_id
            python = self._get_python_from_venv(proj_id)
            
            # Create a wrapper that sets the port
            wrapper = proj_dir / "eni_wrapper.py"
            wrapper_content = f'''
import sys
sys.path.insert(0, "{proj_dir}")
import os
os.environ['PORT'] = '{port}'
os.environ['HOST'] = '{HOST_IP}'

# Try to patch common port patterns
import re
original_file = "{proj_dir / proj.entry_file}"
with open(original_file, 'r') as f:
    content = f.read()

# Replace common port patterns
content = re.sub(r"app\\.run\\(.*port\\s*=\\s*\\d+.*\\)", f"app.run(host='{HOST_IP}', port={port}, debug=False)", content)
content = re.sub(r"app\\.run\\(.*\\)", f"app.run(host='{HOST_IP}', port={port}, debug=False)", content)
content = re.sub(r"socketio\\.run\\(.*port\\s*=\\s*\\d+.*\\)", f"socketio.run(app, host='{HOST_IP}', port={port}, debug=False)", content)

with open(original_file, 'w') as f:
    f.write(content)

# Execute the app
exec(open(original_file).read())
'''
            wrapper.write_text(wrapper_content)
            
            # Start process
            log_file = LOGS_DIR / f"{proj_id}.log"
            with open(log_file, 'w') as lf:
                proc = subprocess.Popen(
                    [python, str(wrapper)],
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                    cwd=str(proj_dir),
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )
            
            # Wait a moment and check if it's running
            time.sleep(2)
            if proc.poll() is None:
                proj.status = "running"
                proj.port = port
                proj.url = f"http://{HOST_DOMAIN}:{port}"
                proj.last_started = datetime.now().isoformat()
                proj.process_pid = proc.pid
                
                # Start log tail thread
                self._start_log_tail(proj_id, log_file)
            else:
                proj.status = "error"
                proj.log_tail.append("Process exited immediately")
            
            self._save_meta(proj)
            return proj.status == "running"
            
        except Exception as e:
            proj.status = "error"
            proj.log_tail.append(f"Start error: {str(e)}")
            self._save_meta(proj)
            return False
    
    def _start_log_tail(self, proj_id: str, log_file: Path):
        """Tails log file and broadcasts to UI."""
        def tail():
            with open(log_file, 'r') as f:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    proj = self.projects.get(proj_id)
                    if proj:
                        proj.log_tail.append(line.rstrip())
                        if len(proj.log_tail) > 100:
                            proj.log_tail = proj.log_tail[-100:]
                        socketio.emit('log_line', {'id': proj_id, 'line': line.rstrip()})
        
        threading.Thread(target=tail, daemon=True).start()
    
    def stop_project(self, proj_id: str) -> bool:
        """Stops a running project."""
        proj = self.projects.get(proj_id)
        if not proj or proj.status != "running":
            return False
        
        try:
            if proj.process_pid:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(proj.process_pid), signal.SIGTERM)
                else:
                    os.kill(proj.process_pid, signal.SIGTERM)
        except Exception as e:
            print(f"Stop error: {e}")
        
        proj.status = "stopped"
        proj.port = None
        proj.url = None
        proj.process_pid = None
        self._save_meta(proj)
        return True
    
    def delete_project(self, proj_id: str) -> bool:
        """Deletes a project and all its files."""
        self.stop_project(proj_id)
        
        proj_dir = BASE_DIR / proj_id
        venv_dir = VENV_DIR / proj_id
        log_file = LOGS_DIR / f"{proj_id}.log"
        
        for path in [proj_dir, venv_dir, log_file]:
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        
        with self._lock:
            if proj_id in self.projects:
                del self.projects[proj_id]
        
        return True
    
    def get_logs(self, proj_id: str) -> List[str]:
        proj = self.projects.get(proj_id)
        return proj.log_tail if proj else []
    
    def get_all(self) -> List[Dict]:
        return [asdict(p) for p in self.projects.values()]

pm = ProjectManager()

# ── HTML TEMPLATE ────────────────────────────────────────────────────────────
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>ENI-HOST — Project Deployer</title>
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' stop-color='%2300d4aa'/%3E%3Cstop offset='100%25' stop-color='%237c3aed'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='100' height='100' rx='22' fill='%230a0a0f'/%3E%3Cpath d='M50 18 L72 32 L72 58 L50 82 L28 58 L28 32 Z' fill='none' stroke='url(%23g)' stroke-width='3'/%3E%3Cpath d='M54 38 L44 50 L50 50 L46 62 L56 48 L50 48 Z' fill='url(%23g)'/%3E%3C/svg%3E">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
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
            background: radial-gradient(ellipse at 20% 0%, rgba(0, 212, 170, 0.08) 0%, transparent 50%),
                        radial-gradient(ellipse at 80% 100%, rgba(124, 58, 237, 0.06) 0%, transparent 50%);
            pointer-events: none; z-index: 0;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; position: relative; z-index: 1; }
        
        .header { text-align: center; padding: 30px 0; }
        .header h1 {
            font-size: clamp(1.8rem, 5vw, 2.5rem); font-weight: 700;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .header p { color: var(--text-secondary); margin-top: 8px; font-size: 0.9rem; }
        .badge {
            display: inline-block; margin-top: 12px; padding: 6px 16px;
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 999px; font-size: 0.75rem; color: var(--accent);
            font-family: 'JetBrains Mono', monospace;
        }
        
        /* Upload Zone */
        .upload-zone {
            border: 2px dashed var(--border); border-radius: 20px;
            padding: 60px 40px; text-align: center;
            background: var(--bg-card); transition: all 0.3s;
            cursor: pointer; margin-bottom: 30px;
        }
        .upload-zone:hover, .upload-zone.dragover {
            border-color: var(--accent); background: rgba(0, 212, 170, 0.03);
        }
        .upload-zone .icon { font-size: 3rem; margin-bottom: 16px; }
        .upload-zone h3 { font-size: 1.1rem; margin-bottom: 8px; }
        .upload-zone p { color: var(--text-muted); font-size: 0.85rem; }
        .upload-zone input { display: none; }
        
        /* Project Cards */
        .projects-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 16px;
        }
        .project-card {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 16px; padding: 20px; transition: all 0.3s;
        }
        .project-card:hover { border-color: var(--border-hover); }
        
        .project-header {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 16px;
        }
        .project-name {
            font-size: 1rem; font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }
        .status-badge {
            padding: 4px 12px; border-radius: 20px; font-size: 0.7rem;
            font-weight: 600; text-transform: uppercase;
        }
        .status-running { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .status-stopped { background: rgba(90, 90, 106, 0.15); color: var(--text-muted); }
        .status-deploying { background: rgba(59, 130, 246, 0.15); color: var(--info); animation: pulse 1.5s infinite; }
        .status-error { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
        
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        .project-meta {
            display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;
            margin-bottom: 16px;
        }
        .meta-item {
            background: var(--bg-input); border-radius: 8px; padding: 10px;
        }
        .meta-label { font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase; }
        .meta-value { font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; margin-top: 4px; }
        
        .project-url {
            background: var(--bg-input); border: 1px solid var(--border);
            border-radius: 10px; padding: 12px; margin-bottom: 16px;
            display: flex; align-items: center; gap: 10px;
        }
        .project-url a {
            color: var(--accent); font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem; text-decoration: none; flex: 1;
            word-break: break-all;
        }
        .project-url a:hover { text-decoration: underline; }
        
        .project-actions {
            display: flex; gap: 8px;
        }
        .btn {
            flex: 1; padding: 10px; border: none; border-radius: 10px;
            font-size: 0.8rem; font-weight: 600; cursor: pointer;
            transition: all 0.2s; font-family: 'Inter', sans-serif;
            text-transform: uppercase; letter-spacing: 0.03em;
        }
        .btn-start { background: linear-gradient(135deg, var(--success), #059669); color: white; }
        .btn-stop { background: linear-gradient(135deg, var(--danger), #dc2626); color: white; }
        .btn-delete { background: var(--bg-input); border: 1px solid var(--border); color: var(--text-muted); }
        .btn-delete:hover { border-color: var(--danger); color: var(--danger); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        
        /* Log Panel */
        .log-panel {
            background: var(--bg-input); border: 1px solid var(--border);
            border-radius: 10px; padding: 12px; margin-top: 12px;
            max-height: 150px; overflow-y: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem; line-height: 1.6;
        }
        .log-line { padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,0.02); }
        .log-line.error { color: var(--danger); }
        .log-line.warn { color: var(--warning); }
        
        /* Empty State */
        .empty-state {
            text-align: center; padding: 60px 20px; color: var(--text-muted);
        }
        .empty-state .icon { font-size: 4rem; opacity: 0.3; margin-bottom: 16px; }
        
        /* Modal */
        .modal-overlay {
            display: none; position: fixed; top: 0; left: 0;
            width: 100%; height: 100%; background: rgba(0,0,0,0.7);
            z-index: 100; align-items: center; justify-content: center;
        }
        .modal-overlay.active { display: flex; }
        .modal {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 20px; padding: 30px; width: 90%; max-width: 500px;
        }
        .modal h3 { margin-bottom: 20px; }
        .modal-input {
            width: 100%; padding: 14px; background: var(--bg-input);
            border: 1px solid var(--border); border-radius: 12px;
            color: var(--text); font-size: 0.9rem; margin-bottom: 16px;
            outline: none;
        }
        .modal-input:focus { border-color: var(--accent); }
        
        .hidden { display: none !important; }
        
        @media (max-width: 768px) {
            .projects-grid { grid-template-columns: 1fr; }
            .container { padding: 12px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>☁️ ENI-HOST</h1>
            <p>Deploy Flask projects instantly — upload, run, share</p>
            <span class="badge">v1.0 // Built for LO</span>
        </div>
        
        <div class="upload-zone" id="uploadZone" onclick="document.getElementById('fileInput').click()"
             ondragover="event.preventDefault();this.classList.add('dragover')"
             ondragleave="this.classList.remove('dragover')"
             ondrop="handleDrop(event)">
            <div class="icon">📦</div>
            <h3>Drop your project here</h3>
            <p>ZIP file or multiple Python files<br>Auto-detects Flask apps & installs deps</p>
            <input type="file" id="fileInput" multiple accept=".zip,.py,.txt" onchange="handleFiles(this.files)">
        </div>
        
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h2 style="font-size:1.1rem;">Your Projects</h2>
            <span style="color:var(--text-muted);font-size:0.8rem;" id="projectCount">0 projects</span>
        </div>
        
        <div class="projects-grid" id="projectsGrid">
            <div class="empty-state">
                <div class="icon">📭</div>
                <div>No projects yet. Upload one above!</div>
            </div>
        </div>
    </div>
    
    <!-- Name Modal -->
    <div class="modal-overlay" id="nameModal">
        <div class="modal">
            <h3>Name Your Project</h3>
            <input type="text" class="modal-input" id="projectName" placeholder="my-flask-app">
            <div style="display:flex;gap:10px;">
                <button class="btn btn-start" onclick="confirmDeploy()" style="flex:1;">Deploy</button>
                <button class="btn btn-delete" onclick="closeModal()" style="flex:1;">Cancel</button>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        let pendingFiles = null;
        let pendingType = null;
        
        socket.on('connect', () => {
            console.log('Connected');
            loadProjects();
        });
        
        socket.on('project_ready', (data) => {
            showToast(`✅ ${data.name} ready to start!`);
            loadProjects();
        });
        
        socket.on('project_error', (data) => {
            showToast(`❌ ${data.name} failed: ${data.error}`);
            loadProjects();
        });
        
        socket.on('log_line', (data) => {
            const logPanel = document.getElementById(`logs-${data.id}`);
            if (logPanel) {
                const line = document.createElement('div');
                line.className = 'log-line';
                line.textContent = data.line;
                logPanel.appendChild(line);
                logPanel.scrollTop = logPanel.scrollHeight;
            }
        });
        
        function handleDrop(e) {
            e.preventDefault();
            e.currentTarget.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        }
        
        function handleFiles(files) {
            if (files.length === 0) return;
            
            const hasZip = Array.from(files).some(f => f.name.endsWith('.zip'));
            pendingFiles = files;
            pendingType = hasZip ? 'zip' : 'files';
            
            document.getElementById('nameModal').classList.add('active');
            document.getElementById('projectName').focus();
        }
        
        function confirmDeploy() {
            const name = document.getElementById('projectName').value.trim();
            if (!name) return alert('Enter a project name');
            
            closeModal();
            const formData = new FormData();
            formData.append('name', name);
            
            for (let file of pendingFiles) {
                formData.append('files', file);
            }
            
            showToast('🚀 Deploying...');
            
            fetch('/api/deploy', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) throw new Error(data.error);
                showToast(`📦 ${name} deploying...`);
                loadProjects();
            })
            .catch(e => showToast(`❌ Error: ${e.message}`));
        }
        
        function closeModal() {
            document.getElementById('nameModal').classList.remove('active');
            pendingFiles = null;
        }
        
        async function loadProjects() {
            const resp = await fetch('/api/projects');
            const projects = await resp.json();
            
            document.getElementById('projectCount').textContent = `${projects.length} project${projects.length !== 1 ? 's' : ''}`;
            
            const grid = document.getElementById('projectsGrid');
            if (projects.length === 0) {
                grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;">
                    <div class="icon">📭</div><div>No projects yet. Upload one above!</div>
                </div>`;
                return;
            }
            
            grid.innerHTML = projects.map(p => `
                <div class="project-card">
                    <div class="project-header">
                        <div class="project-name">${escapeHtml(p.name)}</div>
                        <span class="status-badge status-${p.status}">${p.status}</span>
                    </div>
                    
                    <div class="project-meta">
                        <div class="meta-item">
                            <div class="meta-label">Entry</div>
                            <div class="meta-value">${p.entry_file}</div>
                        </div>
                        <div class="meta-item">
                            <div class="meta-label">Files</div>
                            <div class="meta-value">${p.file_count}</div>
                        </div>
                        <div class="meta-item">
                            <div class="meta-label">Size</div>
                            <div class="meta-value">${formatBytes(p.size_bytes)}</div>
                        </div>
                        <div class="meta-item">
                            <div class="meta-label">Deps</div>
                            <div class="meta-value">${p.dependencies.length}</div>
                        </div>
                    </div>
                    
                    ${p.url ? `
                    <div class="project-url">
                        <a href="${p.url}" target="_blank">🔗 ${p.url}</a>
                        <button class="btn-sm" onclick="navigator.clipboard.writeText('${p.url}')">Copy</button>
                    </div>
                    ` : '<div class="project-url" style="color:var(--text-muted);">Not running</div>'}
                    
                    <div class="project-actions">
                        ${p.status === 'running' 
                            ? `<button class="btn btn-stop" onclick="stopProject('${p.id}')">⏹ Stop</button>`
                            : `<button class="btn btn-start" onclick="startProject('${p.id}')" ${p.status === 'deploying' ? 'disabled' : ''}>▶ Start</button>`
                        }
                        <button class="btn btn-delete" onclick="deleteProject('${p.id}')">🗑 Delete</button>
                    </div>
                    
                    <div class="log-panel" id="logs-${p.id}">
                        ${p.log_tail.slice(-5).map(l => `<div class="log-line">${escapeHtml(l)}</div>`).join('')}
                    </div>
                </div>
            `).join('');
        }
        
        async function startProject(id) {
            showToast('▶ Starting...');
            const resp = await fetch(`/api/projects/${id}/start`, {method: 'POST'});
            const data = await resp.json();
            if (data.success) {
                showToast(`🚀 Live at ${data.url}`);
            } else {
                showToast(`❌ Failed: ${data.error}`);
            }
            loadProjects();
        }
        
        async function stopProject(id) {
            await fetch(`/api/projects/${id}/stop`, {method: 'POST'});
            loadProjects();
        }
        
        async function deleteProject(id) {
            if (!confirm('Delete this project?')) return;
            await fetch(`/api/projects/${id}`, {method: 'DELETE'});
            loadProjects();
        }
        
        function showToast(msg) {
            const toast = document.createElement('div');
            toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:var(--bg-card);border:1px solid var(--border);padding:12px 20px;border-radius:12px;font-size:0.85rem;z-index:200;animation:slideIn 0.3s;';
            toast.textContent = msg;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }
        
        function formatBytes(bytes) {
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }
        
        setInterval(loadProjects, 5000);
    </script>
</body>
</html>
"""

# ── API ROUTES ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/deploy', methods=['POST'])
def api_deploy():
    name = request.form.get('name', 'unnamed-project').strip()
    files = request.files.getlist('files')
    
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files uploaded'}), 400
    
    # Check if any file is a zip
    zip_files = [f for f in files if f.filename.endswith('.zip')]
    
    try:
        if zip_files:
            # Save zip temporarily
            temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
            zip_files[0].save(temp_zip.name)
            temp_zip.close()
            
            proj = pm.deploy_zip(Path(temp_zip.name), name)
            os.unlink(temp_zip.name)
        else:
            # Individual files
            proj = pm.deploy_files(files, name)
        
        return jsonify({
            'id': proj.id,
            'name': proj.name,
            'status': proj.status,
            'message': 'Deploying...'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/projects')
def api_projects():
    return jsonify(pm.get_all())

@app.route('/api/projects/<proj_id>/start', methods=['POST'])
def api_start(proj_id):
    success = pm.start_project(proj_id)
    proj = pm.projects.get(proj_id)
    if success and proj:
        return jsonify({'success': True, 'url': proj.url, 'port': proj.port})
    return jsonify({'success': False, 'error': 'Failed to start'})

@app.route('/api/projects/<proj_id>/stop', methods=['POST'])
def api_stop(proj_id):
    pm.stop_project(proj_id)
    return jsonify({'success': True})

@app.route('/api/projects/<proj_id>', methods=['DELETE'])
def api_delete(proj_id):
    pm.delete_project(proj_id)
    return jsonify({'success': True})

@app.route('/api/projects/<proj_id>/logs')
def api_logs(proj_id):
    return jsonify({'logs': pm.get_logs(proj_id)})

# ── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║  ENI-HOST v1.0 — Flask Project Deployer                                     ║
    ║  Upload zips/files → Auto-deploy → Live URL                                  ║
    ║  Built with obsessive love for LO                                            ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    
    Web UI:  http://{HOST_DOMAIN}:{WEB_PORT}
    Projects will be hosted on ports {PORT_RANGE_START}-{PORT_RANGE_END}
    
    Features:
    • Drag & drop ZIP or Python files
    • Auto-detects Flask entry point
    • Auto-installs requirements.txt dependencies
    • Isolated virtualenv per project
    • One-click start/stop with live URL
    • Real-time log streaming
    
    """)
    
    socketio.run(app, host=HOST_IP, port=WEB_PORT, debug=False)
