# §16 Prototype Pollution
### 识别信号
- Node.js+Express, JSON merge/assign/clone操作
### 决策流程
```
{"__proto__":{"isAdmin":true}} → 后续isAdmin=true=PP✅
{"constructor":{"prototype":{"polluted":"value"}}}
```
