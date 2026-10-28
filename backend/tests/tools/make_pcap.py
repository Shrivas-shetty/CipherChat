"""Build a small deterministic Ethernet/IPv4/TCP classic PCAP for tshark tests."""
import socket
import struct

CLIENT_MAC = bytes.fromhex("020000000020")
SERVER_MAC = bytes.fromhex("020000000010")
CLIENT_IP = "192.168.1.20"
SERVER_IP = "192.168.1.10"


def _frame(src_port, dst_port, seq, ack, flags, payload=b"", client=True):
    src_mac, dst_mac = (CLIENT_MAC, SERVER_MAC) if client else (SERVER_MAC, CLIENT_MAC)
    src_ip, dst_ip = (CLIENT_IP, SERVER_IP) if client else (SERVER_IP, CLIENT_IP)
    eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | flags, 65535, 0, 0)
    ip_len = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, 0x4000, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return eth + ip + tcp + payload


def make_pcap(path):
    frames = []
    cseq, sseq = 1000, 5000
    def add(data, client=True):
        nonlocal cseq, sseq
        if client:
            frames.append(_frame(50000, 8000, cseq, sseq, 0x18, data, True)); cseq += len(data)
        else:
            frames.append(_frame(8000, 50000, sseq, cseq, 0x18, data, False)); sseq += len(data)
    frames.append(_frame(50000, 8000, cseq, 0, 0x02))
    frames.append(_frame(8000, 50000, sseq, cseq + 1, 0x12, client=False))
    frames.append(_frame(50000, 8000, cseq + 1, sseq + 1, 0x10))
    cseq += 1; sseq += 1
    login = b'{"username":"alice","password":"synthetic-not-real"}'
    add(b"POST /api/auth/login HTTP/1.1\r\nHost: cipherchat\r\nContent-Type: application/json\r\nContent-Length: " + str(len(login)).encode() + b"\r\n\r\n" + login)
    token = b'{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}'
    add(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(token)).encode() + b"\r\n\r\n" + token, False)
    body = b'{"message":"SECRETWORD123"}'
    request = b"POST /api/baseline/messages HTTP/1.1\r\nHost: cipherchat\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    marker_at = request.index(b"SECRETWORD123")
    add(request[:marker_at + 6]); add(request[marker_at + 6:])
    response = b'{"id":1}'
    add(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(response)).encode() + b"\r\n\r\n" + response, False)
    frames.append(_frame(50000, 8000, cseq, sseq, 0x11))
    frames.append(_frame(8000, 50000, sseq, cseq + 1, 0x11, client=False))
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames, 1):
            sec, usec = 1700000000, index * 1000
            out.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            out.write(frame)
    return len(frames)
