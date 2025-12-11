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
# 1. Giới thiệu đề bài
 The director of Hogwarts got his account compromised. The last time he logged on legitimately was from 192.168.56.230 (pensive.hogwarts.local). Investigate to identify how his account got compromised from this server. Please find the following information to go forward in this case: - Absolute path of the file which led to the compromise. - Absolute path of the file used by the attacker to retrieve Albus' account. - The second file stores two pieces of information. The 3rd flag part is the value of the second field of the second piece of information. The findings have to be separated by a ";". 

# 2. Giải nén và xem cấu trúc thư mục
  Sau khi extract ta được 2 thư mục chính là:
  {% raw %}{% capture path-highlight %}
     /var/log
     /var/www/glpi
  {% endcapture %}{% endraw %}
  <div class="notice notice--info">{% raw %}{{ path-highlight | markdownify }}{% endraw %}</div>
  Đây là hệ thống **GLPI** – một ứng dụng ITSM thường dính lỗi upload hoặc RCE.  
  Ta bắt đầu phân tích các log.

đây là một mô tả của bài Forensics: The director of Hogwarts got his account compromised. The last time he logged on legitimately was from 192.168.56.230 (pensive.hogwarts.local). Investigate to identify how his account got compromised from this server. Please find the following information to go forward in this case: - Absolute path of the file which led to the compromise. - Absolute path of the file used by the attacker to retrieve Albus' account. - The second file stores two pieces of information. The 3rd flag part is the value of the second field of the second piece of information. The findings have to be separated by a ";". - pensieve_var.7z Here is an example flag format: Hero{/var/idk/file.ext;/var/idk/file.ext;AnExample?} Đây là một write up ngắn: Check log GLPI, thấy attacker khai thác fileupload.php đẩy lên malicious file setup.php, phân tích setup.php -> RCE qua filed save_result. Filter log với "save_result" và decrypt với key và IV -> tiếp tục thấy attacker curl và ghi đè backdoor vào Auth.php -> dump credential bằng cách append vào example.gif. bạn hãy hướng dẫn chi tiết dựa vào những thông tin tôi đã gửi để tìm ra flag