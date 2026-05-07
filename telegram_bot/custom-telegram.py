#!/usr/bin/env python3
import sys
import json
import requests

CHAT_ID = "-5182641908"
TOKEN = "8120297484:AAHrRZ6HXMQxGrHCqiufUpmVGBbE0l5N9JA"

def send_telegram_msg(msg):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {
        'chat_id': CHAT_ID, 
        'text': msg, 
        'parse_mode': 'Markdown'
    }
    try:
        # Cài đặt timeout 5 giây để không làm treo server Wazuh
        response = requests.post(url, data=payload, timeout=5)
        response.raise_for_status()
        print("Đã gửi tin nhắn Telegram thành công!")
    except requests.exceptions.HTTPError as err:
        if response.status_code == 429:
            print("[-] Bị Telegram chặn do quá tải (Rate limit). Đang drop cảnh báo này.")
        else:
            print(f"[-] Lỗi HTTP: {err}")
    except Exception as e:
        print(f"[-] Lỗi gửi Telegram: {e}")

def main():
    # Đọc dữ liệu JSON từ file tạm mà Wazuh truyền vào
    try:
        with open(sys.argv[1], 'r') as alert_file:
            alert_json = json.load(alert_file)
    except FileNotFoundError:
        print(f"Không tìm thấy file: {sys.argv[1]}")
        sys.exit(1)

    # Trích xuất dữ liệu
    rule_id = alert_json.get('rule', {}).get('id', 'N/A')
    description = alert_json.get('rule', {}).get('description', 'N/A')
    level = alert_json.get('rule', {}).get('level', 'N/A')
    agent_name = alert_json.get('agent', {}).get('name', 'Wazuh Server')
    
    # Định dạng tin nhắn
    msg = f"🚨 *WAZUH SOC ALERT* 🚨\n"
    msg += f"*Level:* {level}\n"
    msg += f"*Mô tả:* {description}\n"
    msg += f"*Agent:* {agent_name}\n"
    msg += f"*Rule ID:* {rule_id}\n"
    
    send_telegram_msg(msg)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        print("LỖI: Vui lòng truyền tham số đường dẫn file alert.json")
