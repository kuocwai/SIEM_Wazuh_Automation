#!/usr/bin/env python3
import sys
import json
import requests
import ipaddress
import logging

# Thiết lập bộ ghi log để dễ dàng debug nếu API bị lỗi
logging.basicConfig(
    filename='/var/ossec/logs/integrations.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s custom-abuseipdb: %(message)s'
)

def is_public_ip(ip_str):
    """Kiểm tra xem IP có phải là IP Public (Internet) hay không"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False

def main():
    # 1. Đọc tham số từ Wazuh truyền xuống
    if len(sys.argv) < 4:
        logging.error("Thiếu tham số truyền vào từ Wazuh Integrator.")
        return

    alert_file_path = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3] # https://api.abuseipdb.com/api/v2/check

    # 2. Đọc nội dung alert
    try:
        with open(alert_file_path) as f:
            alert = json.load(f)
    except Exception as e:
        logging.error(f"Không thể đọc file alert gốc: {e}")
        return

    # 3. Lấy IP của kẻ tấn công
    srcip = alert.get("data", {}).get("srcip") or alert.get("srcip")
    if not srcip:
        return

    # [FIX CỰC MẠNH] Bỏ qua các dải IP nội bộ (LAN) để không làm lãng phí lượt gọi API
    if not is_public_ip(srcip):
        logging.info(f"Bỏ qua IP nội bộ: {srcip}")
        return

    # 4. Gọi API AbuseIPDB
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': srcip, 'maxAgeInDays': '90'}
    
    try:
        response = requests.get(hook_url, headers=headers, params=params, timeout=10)
        
        # [FIX CỰC MẠNH] Xử lý dứt điểm lỗi Rate Limit (HTTP 429)
        if response.status_code == 429:
            logging.warning(f"RATE LIMITED (HTTP 429)! Đã hết lượt gọi API AbuseIPDB cho IP {srcip}")
            return
            
        if response.status_code == 200:
            data = response.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)

            # 5. Nếu IP có độ tin cậy độc hại (score >= 0 để test)
            if score >= 0:
                log_output = {
                    "integration": "abuseipdb",
                    "ip": srcip,
                    "score": score,
                    "country": data.get('countryCode', 'Unknown'),
                    "usageType": data.get('usageType', 'Unknown'), # Lấy thêm loại mạng (ISP/DataCenter)
                    "description": "Phat hien IP doc hai tu AbuseIPDB"
                }
                # Ghi đè vào file active-responses.log để Rule 100099 bắt được
                with open("/var/ossec/logs/active-responses.log", "a") as ar_log:
                    ar_log.write(json.dumps(log_output) + "\n")
                
                logging.info(f"Đã tra cứu thành công IP {srcip} - Score: {score}")
        else:
            logging.error(f"Lỗi từ AbuseIPDB. Status Code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        # [FIX CỰC MẠNH] Bắt lỗi rớt mạng/timeout cụ thể, không dùng 'pass' mù quáng
        logging.error(f"Lỗi kết nối mạng đến máy chủ AbuseIPDB: {e}")

if __name__ == "__main__":
    main()
