# §27 前端鉴权绕过（响应包修改 + JS校验绕过）
### 识别信号
```
两种入口信号（满足任一即进本§）:

信号A — 响应包修改类(场景A-H):
  · API返回正确的数据但前端401弹窗/提示无权限
  · Burp中看到API返回了数据但页面不展示
  · 前端JS中有 if(res.ok) / if(res.status==200) / if(data.success) 校验

信号B — 路由防御类(场景I-L):
  · 点击管理功能点 → 被重定向到登录页或403
  · JS中搜到 beforeEach / beforeEnter / addRoute 等路由守卫代码
  · 已知有 /admin /manage 等路径但登录后访问仍跳转
```

### 核心思路
```
两种绕过路径（根据入口信号选一种）:

路径1 — 改响应包(入口信号A):
  后端没鉴权/鉴权不全,前端自己做了层校验。
  你只需要在Burp中改响应包状态码/字段,让前端展示本不该看到的数据。

路径2 — 路由注入(入口信号B):
  前端路由守卫只在"导航时"拦截,不阻止"已注册路由"。
  找到守卫逻辑漏洞(beforeEach只查login不查role)、
  或直接用router.addRoute()在控制台注入隐藏路由,
  就能让前端渲染你本不该看到的页面。
```

### 路由防御识别（先判断目标用了哪种防御模式）
```
拿到JS源码后,搜以下关键词判断路由防御类型:

搜 routes: [ 或 const routes = [
  → 找到所有静态路由定义(/login /register /404 /admin /dashboard等)
  → 区分: 哪些路径始终可访问(静态),哪些需要权限才显示(动态)
  → 直接浏览器访问所有找到的路径,看哪些不需要登录

搜 beforeEach (全局前置守卫)
  → 分析守卫逻辑: 哪些路径要auth、哪些不要、role检查怎么做的
  → 常见漏洞: 只检查了 isLoggedIn() 没检查角色
  → 常见漏洞: 写了 return 但没阻止导航(return true / undefined 会放行)
  → 常见漏洞: 数组形式的守卫只执行了第一个

搜 addRoute / addRoutes (动态路由注入)
  → 找到"登录后根据权限添加路由"的逻辑
  → 关键: 如果有 convertMenuToRoute 函数 → 分析路径拼接规则
  → 有了规则就能猜: 已知 /dashboard → 拼出 /dashboard-manage /dash/settings

搜 meta.requiresAuth / meta.role / beforeEnter
  → 找出哪些路径标了需要什么角色
  → 如果只标了 requiresAuth: true 没标 role → 登录后就能访问

搜 /api/user/info 或 /api/menuList 或 getMenu (权限菜单接口)
  → 响应里返回 menulist / routes / permissions 数组
  → 如果改响应包里的 menulist → 前端会 addRoute 添加更多路由
```

### 场景判断树
```
发现API返回200但页面不展示数据?

├── 场景A: 状态码校验
│   ├── 后端返回401 → 前端收到就隐藏数据
│   └── Burp将401改成200 → 数据出现 ✅
│
├── 场景B: JSON字段校验
│   ├── 后端返回{"success":false,"code":401,"data":[...]}
│   └── Burp改成{"success":true,"code":200,"data":[...]} → 数据出现 ✅
│
├── 场景C: response.ok校验
│   ├── JS代码: if(res.ok){显示数据}else{弹窗}
│   └── Burp保证响应状态码200+返回数据 → 绕过 ✅
│
├── 场景D: 前端鉴权Token校验
│   ├── JS从localStorage取Token → 没有Token时隐藏/跳转
│   └── 在当前页面注入Token到localStorage → 再刷新页面 → 接口返回正常数据 ✅
│
├── 场景E: 前端路由鉴权
│   ├── Vue/React路由守卫 → 只允许admin角色访问
│   └── 直接curl调用API(绕过前端) → API可能没鉴权 → 数据出现 ✅
│
├── 场景F: 权限菜单响应替换法（垂直越权最聪明的方式）
│   ├── 用管理员账号登录→抓取权限菜单接口的完整响应
│   ├── 把这份完整响应替换给子账号的权限菜单接口
│   ├── 子账号刷新后界面出现所有管理员功能点→直接点击测试
│   └── 如果功能点可访问→垂直越权确认
│       不需要手动猜管理员接口,页面已经全部列出来了
│
├── 场景G: 浏览器回退绕过（自动跳转场景）
│   ├── 登录后页面自动跳转（index→特定页面，一闪而过）
│   ├── 自动跳转走完后→点浏览器左上角回退按钮
│   ├── 利用浏览器缓存+栈结构→回到了跳转前的管理页面
│   └── 此时可能已经是未授权/高权限状态 ✅
│       原理: 跳转脚本已执行完毕,缓存的页面没有再做二次校验
│
└── 场景H: 按钮灰色/未激活 → 直接URL访问绕过UI限制
    ├── 页面上某个按钮灰色不可点(disabled)或提示"未激活"
    ├── 但这种页面通常就是路由层面允许的,只是前端限制了UI入口
    ├── 直接复制当前页面的URL路径,新标签页打开或手动拼接
    └── → 如果路由对你开放 → 绕过前端限制 ✅
        常见: 试用期禁用功能、账号未激活的个人中心、VIP专享页面

发现路由守卫拦截(跳转登录/403)?

├── 场景I: 路由定义搜索 → 从JS源码找到隐藏路径
│   ├── 在JS中搜 path: '/' 和 path: '/xxx' 收集所有路由定义
│   ├── 区分: 静态路由(始终可访问,在routes数组里) vs 动态路由(登录后addRoute)
│   ├── 静态路由 → 直接浏览器URL访问,不需要登录
│   │   常见: 开发时把/admin /manage放在静态路由表里忘了改
│   └── 动态路由 → 找 addRoute 的调用位置 + 分析权限菜单接口响应
│
├── 场景J: beforeEach守卫绕过 → 分析守卫逻辑找漏洞
│   ├── 找到JS中的 beforeEach 函数,看判断逻辑:
│   │   ├── 只检查了token存在性但没校验角色? → 普通用户登录后可访问admin路由
│   │   ├── return 写错了(return undefined / return true 但实际没阻止)?
│   │   ├── 守卫是数组形式但只执行了第一个?
│   │   └── 动态路由添加后 next({...to, replace:true}) 重新触发导航时守卫已过?
│   └── 直接在浏览器控制台调试:
│       localStorage.setItem('token', '任意值')
│       再刷新 → 看守卫是否放行了 /admin 路径
│
├── 场景K: 动态路由手动添加 → 控制台注入路由
│   ├── 原理: 路由守卫只拦截"导航行为",不拦截"已注册路由"
│   ├── 操作: 在浏览器F12控制台执行
│   │   // 找到router实例
│   │   const vm = document.querySelector('#app').__vue_app__
│   │   const router = vm.config.globalProperties.$router
│   │   // 手动添加管理员路由
│   │   router.addRoute({ path: '/admin/users', name: 'admin-users',
│   │     component: () => import('@/views/admin/UserManage.vue') })
│   │   // 导航过去
│   │   router.push('/admin/users')
│   │
│   ├── 如果路由注册成功 → 绕过前端守卫 ✅
│   ├── 找component路径: 在JS源码中搜 views/ 或 pages/ 找已有组件路径
│   └── 配合同源路径推测: 已知 /dashboard → 猜 /dashboard-manage 组件也存在
│
└── 场景L: 路径前缀发现其他角色入口
    ├── 发现 /worker/index → 猜 /admin/index /manage/index 也存在
    ├── 同一个站可能有多套路由表对应不同角色(路径前缀不同)
    ├── 直接浏览器访问 /admin/index → 看路由守卫是否拦截
    └── 如果没拦截 → 垂直越权 ✅
        常见于: 后台管理系统,超级管理员/普通管理员共用一套但前缀不同
```

### 辅助字段速查（改响应包时重点关注）
```
不是所有绕过都是改401→200。以下字段改了可能直接提权:

super_user_force → super_user_true    (管理员权限提升)
isActive:0 → isActive:1               (账号激活绕过)
isShow:0 → isShow:1                   (菜单显示控制)
isAdmin:false → isAdmin:true          (管理员标识)
role:user → role:admin                 (角色提权)
level:0 → level:1                      (权限等级提升)
status:inactive → status:active        (状态绕过)
```

### 找路由+接口技巧（JS源码分析专用）
```
1. 搜路由定义:
   routes: [         → 全部路由路径清单
   path: '/'         → 每条路由的具体路径
   component: () => import → 组件的物理路径(知道路径就能猜其他页面)
   name: 'xxx'       → 路由名称

2. 搜守卫逻辑:
   beforeEach        → 全局前置守卫(鉴权核心逻辑)
   beforeEnter       → 路由独享守卫(特定路径的权限控制)
   meta.requiresAuth → 标记哪些路径需要登录
   meta.role         → 标记哪些路径需要特定角色
   requireAuth       → 守卫函数名

3. 搜动态路由:
   addRoute / addRoutes   → 动态添加路由的位置
   convertMenuToRoute     → 菜单→路由转换函数(暴露路径命名规则)
   filterRoutes / filterAsyncRoutes → 路由过滤函数

4. 搜权限菜单接口:
   getMenu / getRouters / getResource / getPermission
   menuList / menus / authRoutes / permissionList

5. 搜组件路径(知道了就能猜):
   @/views/xxx       → Vue组件路径
   ./pages/xxx       → 小程序/React组件路径
   /components/xxx   → 组件目录

6. 同源功能点推测:
   已知接口 /api/crowd/count_by_condition
   → 猜 /api/crowd/save_by_condition (count→save)
   → 猜 /api/crowd/delete_by_condition (count→delete)
   核心: 操作同一数据的接口名,只有动词不同

7. 反斜杠路径:
   JS里路径写的是 \\log\\ 而不是 /log/
   → 常规搜索搜不到 → 手动构造 /log/ 访问
   → 常见于开发者有意隐藏接口

8. 一个接口泄露全站API清单:
    有些权限/配置接口的响应中会返回所有可用接口的路径+参数
    → 重点查 getRowInfo / getMenu / getResource 等响应
    → 发现了就直接获得全站攻击面

9. 空数据 ≠ 没价值（重要认知）:
    路由接口返回 [] 或 {"data":[]} 时:
    → 接口能访问(无鉴权/鉴权已过) = 攻击面已打开
    → 即使数据为空,返回的JSON结构暴露了:
       字段名(知道对方存了什么数据)
       参数名(知道怎么构造请求)
       可能的枚举值
    → 下一步: 用这些结构信息去猜其他接口是否存在
       返回了 {"users":[]} → 猜 /api/users/create 也存在
       返回了 {"files":[]} → 猜 /api/files/upload 也存在
```

### 决策流程
```
入口判断: 遇到的是哪种信号?

→ 信号A(API有数据但页面不展示):
  Step1: Burp拦截响应 → 看状态码和JSON结构
  Step2: 401/403 → 改成200 | false改true → 放行给前端
  Step3: 数据出现 → 前端鉴权绕过确认 ✅
  Step4: 同时试试curl直接调API → 看后端是不是也没鉴权

→ 信号B(路由跳转登录/403):
  Step1: JS中搜 path: / routes: [ / beforeEach / addRoute
         收集所有路由路径 + 守卫逻辑
  Step2: 浏览器逐个访问发现的路由 → 看哪些不需要登录/角色
  Step3: 分析beforeEach → 找只查login不查role的漏洞
  Step4: 控制台 router.addRoute({path:'/admin/xxx'}) → 手动注入路由
  Step5: 发现 /worker/ 前缀 → 猜 /admin/ 也存在 → 直接访问

→ 自动跳转场景(登录后一闪而过):
  浏览器回退 → 看能否回到高权限页面

→ 按钮灰色场景:
  直接URL访问 → 看路由是否对当前用户开放
```

---
