# §18 API数据联动
### 核心
```
接口A响应字段 → 输入到接口B/C/D请求参数
userId → /api/user/info?userId=  orderId → /api/order/detail?orderId=
token → Auth头  teamId → /api/team/members?teamId=
```
### 流程
```
每获响应→提取ID字段→匹配已知接口→替换值测越权→记录联动表
```
### 常见链
```
链1: 登录→{userId,token} → 用token访问他人userId=IDOR | 解码JWT改role
链2: 列表→{orderId} → 遍历其他orderId测可枚举
链3: 详情→{fileUrl,ownerId} → 下载/删除他人文件

关联: SKILL.md §3 Response Chaining (core principle) — 两条互补阅读
```
