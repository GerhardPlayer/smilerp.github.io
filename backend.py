#!/usr/bin/env python3
"""API do GMod Server Checker; o frontend é publicado separadamente no GitHub Pages."""
import json
import os
import re
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ALLOWED_ORIGINS = {x.strip() for x in os.environ.get("ALLOWED_ORIGINS", "").split(",") if x.strip()}
ALLOWED_SERVERS = {x.strip() for x in os.environ.get("ALLOWED_SERVERS", "131.196.196.198:27015").split(",") if x.strip()}
MAX_REQUESTS = 12
WINDOW_SECONDS = 60
RATE_LOCK = threading.Lock()
REQUESTS = {}

HEAD = b"\xff\xff\xff\xff"
TIMEOUT = 3.0


class Reader:
    def __init__(self, data):
        self.d, self.i = data, 0

    def byte(self):
        v = self.d[self.i]; self.i += 1; return v

    def short(self):
        v = struct.unpack_from("<H", self.d, self.i)[0]; self.i += 2; return v

    def long_long(self):
        v = struct.unpack_from("<Q", self.d, self.i)[0]; self.i += 8; return v

    def float(self):
        v = struct.unpack_from("<f", self.d, self.i)[0]; self.i += 4; return v

    def int(self):
        v = struct.unpack_from("<i", self.d, self.i)[0]; self.i += 4; return v

    def cstr(self):
        end = self.d.index(b"\x00", self.i)
        s = self.d[self.i:end].decode("utf-8", "replace")
        self.i = end + 1
        return s

    def left(self):
        return len(self.d) - self.i


def recv_packet(sock):
    """Recebe um pacote, remontando respostas fragmentadas (-2)."""
    data = sock.recv(4096)
    if data[:4] != b"\xfe\xff\xff\xff":
        return data[4:] if data[:4] == HEAD else data
    parts, total = {}, None
    while True:
        r = Reader(data[4:])
        r.int()                       # id
        total = r.byte()
        num = r.byte()
        r.short()                     # tamanho do fragmento
        parts[num] = data[4 + r.i:]
        if len(parts) >= total:
            break
        data = sock.recv(4096)
    full = b"".join(parts[k] for k in sorted(parts))
    return full[4:] if full[:4] == HEAD else full


def request(sock, addr, payload):
    """Envia um pedido e trata o 'challenge' que servidores novos exigem."""
    sock.sendto(HEAD + payload, addr)
    resp = recv_packet(sock)
    if resp and resp[0] == 0x41:                 # challenge
        sock.sendto(HEAD + _with_challenge(payload, resp[1:5]), addr)
        resp = recv_packet(sock)
    return resp


def _with_challenge(payload, challenge):
    if payload[:1] == b"T":                      # A2S_INFO: challenge no fim
        return payload + challenge
    return payload[:1] + challenge               # A2S_PLAYER: challenge no lugar do -1


def parse_info(data):
    r = Reader(data)
    r.byte()                                     # 0x49
    info = {"protocol": r.byte(), "name": r.cstr(), "map": r.cstr(),
            "folder": r.cstr(), "game": r.cstr(), "app_id": r.short(),
            "players": r.byte(), "max_players": r.byte(), "bots": r.byte()}
    info["type"] = {"d": "Dedicado", "l": "Listen", "p": "SourceTV"}.get(chr(r.byte()), "?")
    info["os"] = {"l": "Linux", "w": "Windows", "m": "Mac", "o": "Mac"}.get(chr(r.byte()), "?")
    info["password"] = bool(r.byte())
    info["vac"] = bool(r.byte())
    info["version"] = r.cstr()
    if r.left():
        edf = r.byte()
        if edf & 0x80: info["port"] = r.short()
        if edf & 0x10: r.long_long()
        if edf & 0x40: r.short(); r.cstr()
        if edf & 0x20: info["tags"] = r.cstr()
    return info


def parse_players(data):
    r = Reader(data)
    r.byte()                                     # 0x44
    count, players = r.byte(), []
    for _ in range(count):
        if r.left() < 9:
            break
        r.byte()                                 # índice
        name, score, dur = r.cstr(), r.int(), r.float()
        players.append({"name": name or "(conectando...)", "score": score,
                        "time": int(dur)})
    return players


def query(host, port):
    addr = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        t0 = time.perf_counter()
        raw = request(sock, addr, b"TSource Engine Query\x00")
        ping = round((time.perf_counter() - t0) * 1000)
        if not raw or raw[0] != 0x49:
            return {"online": False, "error": "Resposta inválida do servidor"}
        info = parse_info(raw)
        info.update(online=True, ping=ping, ip=host, query_port=port)
        try:
            praw = request(sock, addr, b"U\xff\xff\xff\xff")
            info["player_list"] = parse_players(praw) if praw and praw[0] == 0x44 else []
        except (socket.timeout, OSError, IndexError, struct.error):
            info["player_list"] = []
        return info
    except socket.timeout:
        return {"online": False, "error": "Sem resposta (offline, porta errada ou query bloqueada)"}
    except (socket.gaierror, OSError) as e:
        return {"online": False, "error": f"Não foi possível conectar: {e}"}
    except (IndexError, struct.error, ValueError):
        return {"online": False, "error": "Resposta ilegível do servidor"}
    finally:
        sock.close()


def parse_addr(text):
    """Aceita apenas destinos fixos autorizados; nunca recebe host arbitrário."""
    text = text.strip()
    if not text or len(text) > 255 or text not in ALLOWED_SERVERS or ":" not in text:
        raise ValueError("Servidor não autorizado")
    host, raw_port = text.rsplit(":", 1)
    if not re.fullmatch(r"[0-9.]+", host):
        raise ValueError("Destino permitido deve ser IPv4 fixo")
    try:
        socket.inet_aton(host)
        port = int(raw_port)
    except (OSError, ValueError):
        raise ValueError("Endereço inválido")
    if not 1 <= port <= 65535:
        raise ValueError("Porta inválida")
    return host, port

def rate_limited(ip):
    now = time.monotonic()
    with RATE_LOCK:
        hits = [t for t in REQUESTS.get(ip, []) if now - t < WINDOW_SECONDS]
        if len(hits) >= MAX_REQUESTS:
            REQUESTS[ip] = hits
            return True
        hits.append(now)
        REQUESTS[ip] = hits
        if len(REQUESTS) > 2000:
            for old_ip in list(REQUESTS)[:500]:
                REQUESTS.pop(old_ip, None)
        return False

class Handler(BaseHTTPRequestHandler):
    server_version = "GModCheckerAPI"
    sys_version = ""

    def _send(self, code, payload, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        origin = self.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        if self.headers.get("Origin", "") not in ALLOWED_ORIGINS:
            self._send(403, {"error": "Origem não autorizada"})
            return
        self._send(204, b"", "text/plain; charset=utf-8")

    def do_GET(self):
        url = urlparse(self.path)
        if url.path != "/api/query":
            self._send(404, {"error": "Not found"})
            return
        origin = self.headers.get("Origin", "")
        if origin and origin not in ALLOWED_ORIGINS:
            self._send(403, {"online": False, "error": "Origem não autorizada"})
            return
        if rate_limited(self.client_address[0]):
            self._send(429, {"online": False, "error": "Muitas consultas. Aguarde um minuto."})
            return
        addr = parse_qs(url.query).get("addr", [""])[0]
        try:
            host, port = parse_addr(addr)
        except ValueError:
            self._send(403, {"online": False, "error": "Servidor não autorizado", "addr": addr})
            return
        result = query(host, port)
        result["addr"] = addr
        self._send(200, result)

    def log_message(self, *_args):
        pass

if __name__ == "__main__":
    if not ALLOWED_ORIGINS:
        raise SystemExit("Configure ALLOWED_ORIGINS com a origem exata do GitHub Pages.")
    if not ALLOWED_SERVERS:
        raise SystemExit("Configure ALLOWED_SERVERS com ao menos um IP:porta.")
    port = int(os.environ.get("PORT", "8000"))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"GMod Checker API ouvindo na porta {port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
