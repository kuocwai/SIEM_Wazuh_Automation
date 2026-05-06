#!/bin/bash

# Thư mục chứa file backup (sẽ tạo nếu chưa có)
BACKUP_DIR="/root/wazuh_backups"
mkdir -p "$BACKUP_DIR"

# Lấy ngày giờ hiện tại để đặt tên file
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/wazuh_config_backup_$TIMESTAMP.tar.gz"

echo "[*] Kiem tra thu muc he thong Wazuh..."

# KIỂM TRA SỰ TỒN TẠI CỦA 2 THƯ MỤC TRƯỚC KHI NÉN
if [ ! -d "/var/ossec/etc" ] || [ ! -d "/var/ossec/ruleset" ]; then
    echo "[-] LỖI: Khong tim thay /var/ossec/etc hoac /var/ossec/ruleset."
    echo "[-] Vui long kiem tra xem Nghia da cai xong Wazuh Manager chua nhe!"
    exit 1 # Dừng script ngay lập tức nếu không tìm thấy
fi

echo "[*] Thu muc ton tai. Dang bat dau backup cau hinh Wazuh Manager..."

# Nén 2 thư mục quan trọng nhất
tar -czvf "$BACKUP_FILE" /var/ossec/etc /var/ossec/ruleset > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "[+] Backup thanh cong! File duoc luu tai: $BACKUP_FILE"
    
    # Dọn dẹp các file backup cũ hơn 7 ngày để giải phóng ổ cứng
    find "$BACKUP_DIR" -name "wazuh_config_backup_*.tar.gz" -type f -mtime +7 -exec rm -f {} \;
    echo "[*] Da don dep cac file backup cu hon 7 ngay (neu co)."
else
    echo "[-] LỖI: Backup that bai. Vui long kiem tra lai quyen (thu chay bang root)."
fi
