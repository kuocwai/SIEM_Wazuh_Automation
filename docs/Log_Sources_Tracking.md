# BẢNG THEO DÕI TIẾN ĐỘ NGUỒN LOG (LOG SOURCES TRACKING)
*Mục đích: Theo dõi tiến độ đẩy log từ hạ tầng về Wazuh để Thái có dữ liệu test Rule và viết query Threat Hunting.*
*Deadline hoàn thành đẩy log: 20/05/2026.*

| STT | Nguồn Log (Log Source) | Thiết bị / Hostname | Địa chỉ IP (Nghĩa điền) | Loại sự kiện cần có (Event Types) | Trạng thái đẩy log |
|---|---|---|---|---|---|
| 1 | **Wazuh Agent (Windows)** | Windows Endpoint Lab | `[Nghĩa điền vào đây]` | Logon, Process Creation, User Auth | ⏳ Chờ Nghĩa cài |
| 2 | **Wazuh Agent (Linux)** | Ubuntu Server / Kali | `[Nghĩa điền vào đây]` | SSH Auth, Sudo execution, Cronjob | ⏳ Chờ Nghĩa cài |
| 3 | **Sysmon (Windows)** | Windows Endpoint Lab | `[Nghĩa điền vào đây]` | Sysmon Event ID 1 (Process), 3 (Network), 11 (File) | ⏳ Chờ cấu hình |
| 4 | **FIM (File Integrity)** | Windows & Linux VMs | `[Nghĩa điền vào đây]` | Sửa/Xóa/Tạo file quan trọng (vd: `/etc/passwd` hoặc `System32`) | ⏳ Chờ kích hoạt |
| 5 | **Syslog (Network)** | Tường lửa giả lập / Router | `[Nghĩa điền vào đây]` | Traffic bị drop, Firewall block IP | ⏳ Chờ cấu hình |

**Ghi chú cho Nghĩa (Sysadmin):** Khi ông cài xong con máy nào và cấu hình đẩy log thành công, ông vào file này edit cái IP và đổi trạng thái thành `✅ Đã có log` nhé!
