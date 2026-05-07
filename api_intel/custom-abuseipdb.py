#!/usr/bin/env python3
import sys
import json
import requests

def main():
    # Lấy đường dẫn file log và API Key do Manager truyền vào
    alert_file_path = sys.argv[1]
    api_key = sys.argv[2]

    # 1. Đọc dữ liệu cảnh báo
    try:
        with open(alert_file_path) as f:
            alert = json.load(f)
    except FileNotFoundError:
        sys.exit(1)

    # 2. Tìm kiếm địa chỉ IP (srcip) trong log
    srcip = alert.get("data", {}).get("srcip") or alert.get("srcip")
    
    # Bỏ qua nếu log không có IP hoặc là IP nội bộ (localhost)
    if not srcip or srcip.startswith("127.") or srcip.startswith("192.168."):
        sys.exit(0)

    # 3. Gửi IP lên AbuseIPDB để kiểm tra
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': srcip, 'maxAgeInDays': '90'}
    
    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            
            # 4. Nếu điểm độc hại > 0, trả dữ liệu lại cho Wazuh
            if score > 0:
                alert_output = {
                    "integration": "custom-abuseipdb",
                    "abuseipdb_info": data,
                    "original_alert": alert.get("id")
                }
                # Dòng print này chính là cách giao tiếp với Wazuh
                print(json.dumps(alert_output))
    except Exception:
        sys.exit(0) # Có lỗi thì tự động thoát, không làm treo server

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        main()
