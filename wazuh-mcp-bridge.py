#!/usr/bin/env python3
"""
Wazuh MCP Bridge - Native Python stdio MCP proxy
Starts the Wazuh MCP HTTP server and bridges stdio <-> HTTP without mcp-remote.
No stderr output = no MCP Error indicator in Antigravity.
"""
import os
import sys
import time
import json
import socket
import subprocess
import threading
import urllib.request
import urllib.error
from pathlib import Path

# Silencia todo stderr para evitar MCP Error no Antigravity
sys.stderr = open(os.devnull, 'w')

# === Configurações ===
SERVER_DIR = Path(__file__).parent
ENV_FILE = SERVER_DIR / ".env"
HOST = "127.0.0.1"
PORT = 3000
MCP_URL = f"http://{HOST}:{PORT}/mcp"

def load_env():
    """Carrega variáveis do .env"""
    if ENV_FILE.exists():
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())

def is_server_running():
    """Verifica se o servidor já está na porta"""
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except (ConnectionRefusedError, OSError):
        return False

def start_server():
    """Inicia o servidor Wazuh MCP HTTP em background"""
    load_env()
    env = os.environ.copy()
    src_path = str(SERVER_DIR / "src")
    existing_pythonpath = env.get("PYTHONPATH", "")
    pythonpath = f"{src_path}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else src_path
    env.update({
        "PYTHONPATH": pythonpath,
        "MCP_HOST": HOST,
        "MCP_PORT": str(PORT),
        "AUTH_MODE": "none",
        "AUTHLESS_ALLOW_WRITE": "true",
        "LOG_LEVEL": "ERROR",
        "WAZUH_VERIFY_SSL": "false",
        "WAZUH_ALLOW_SELF_SIGNED": "true",
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "wazuh_mcp_server"],
        cwd=str(SERVER_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(30):
        if is_server_running():
            return proc
        time.sleep(0.5)
    return proc

def send_http(payload: dict) -> dict | None:
    """Envia JSON-RPC para o servidor HTTP e retorna a resposta"""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        MCP_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            if raw:
                return json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError):
        pass
    return None

def write_response(obj: dict):
    """Escreve uma resposta JSON-RPC no stdout"""
    line = json.dumps(obj, ensure_ascii=False)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()

def main():
    server_proc = None

    # Sobe o servidor se não estiver rodando
    if not is_server_running():
        server_proc = start_server()

    # Loop de leitura stdio (newline-delimited JSON-RPC)
    try:
        for raw_line in sys.stdin:
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                msg = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            method = msg.get("method", "")
            msg_id = msg.get("id")

            # initialize: responder localmente sem ir ao servidor
            if method == "initialize":
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": "wazuh-mcp-bridge",
                            "version": "1.0.0"
                        }
                    }
                })
                # Enviar initialized notification
                write_response({"jsonrpc": "2.0", "method": "notifications/initialized"})
                continue

            # notifications (sem id) → apenas repassar ao servidor
            if msg_id is None:
                send_http(msg)
                continue

            # tools/list, tools/call, resources/* → repassar ao servidor HTTP
            resp = send_http(msg)
            if resp:
                write_response(resp)
            else:
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": "Wazuh MCP server unreachable"
                    }
                })

    except (KeyboardInterrupt, BrokenPipeError, EOFError):
        pass
    finally:
        if server_proc:
            server_proc.terminate()

if __name__ == "__main__":
    main()
