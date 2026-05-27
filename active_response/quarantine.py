#!/usr/bin/env python3
# ============================================================
# FILE: custom-quarantine.py
# CHỨC NĂNG: Cách ly máy trạm (Endpoint) khỏi mạng, chỉ giữ kết nối đến Wazuh Manager.
# ============================================================

import sys
import json
import os
import subprocess

# Cấu hình IP của Wazuh Manager (Nơi máy trạm cần gửi log về)
WAZUH_MANAGER_IP = "192.168.0.11" 
LOG_FILE = "/var/ossec/logs/active-responses.log"

def write_log(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def quarantine_linux_endpoint():
    """
    Sử dụng iptables để chặn toàn bộ kết nối In/Out, ngoại trừ:
    - Loopback (127.0.0.1)
    - Kết nối với Wazuh Manager (TCP/UDP port 1514, 1515)
    """
    try:
        # Bước 1: Cho phép giao tiếp nội bộ (loopback)
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)

        # Bước 2: Cho phép giao tiếp với Wazuh Manager (để gửi log và nhận lệnh gỡ cách ly)
        subprocess.run(["iptables", "-A", "INPUT", "-s", WAZUH_MANAGER_IP, "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", WAZUH_MANAGER_IP, "-j", "ACCEPT"], check=True)

        # Bước 3: Chặn sạch sẽ phần còn lại (DROP all In/Out)
        subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
        subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)

        return True
    except subprocess.CalledProcessError as e:
        write_log(f"custom-quarantine: Lỗi khi thực thi iptables - {e}")
        return False

def unquarantine_linux_endpoint():
    """
    Xóa bỏ lệnh phong tỏa, đưa iptables về trạng thái bình thường (ACCEPT)
    """
    try:
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
        # Flush (Xóa) các rule cấm đã thêm
        subprocess.run(["iptables", "-F"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        write_log(f"custom-quarantine: Lỗi khi gỡ iptables - {e}")
        return False

def main():
    # 1. Đọc dữ liệu (JSON) do Wazuh đẩy vào từ standard input
    input_data = sys.stdin.readline()
    if not input_data:
        write_log("custom-quarantine: Không nhận được dữ liệu đầu vào.")
        sys.exit(1)

    try:
        alert = json.loads(input_data)
        
        # 2. Kiểm tra đây là lệnh ADD (Phong tỏa) hay DELETE (Gỡ phong tỏa)
        command = alert.get("command")
        agent_id = alert.get("parameters", {}).get("alert", {}).get("agent", {}).get("id")

        if command == "add":
            success = quarantine_linux_endpoint()
            if success:
                write_log(f"custom-quarantine: [ADD] Đã CÁCH LY THÀNH CÔNG Agent ID {agent_id}.")
        
        elif command == "delete":
            success = unquarantine_linux_endpoint()
            if success:
                write_log(f"custom-quarantine: [DELETE] Đã GỠ CÁCH LY cho Agent ID {agent_id}.")
        else:
             write_log(f"custom-quarantine: Lệnh không hợp lệ: {command}")

    except json.JSONDecodeError:
        write_log("custom-quarantine: Dữ liệu đầu vào không phải định dạng JSON.")
        sys.exit(1)
    except Exception as e:
        write_log(f"custom-quarantine: Lỗi không xác định - {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
