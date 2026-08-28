/**
 * scripts/snow_eyes_inject.js — 雪瞳前端信息快速提取 (v1.1)
 *
 * Pure JavaScript — no extension API dependencies.
 * Inject via chrome-devtools evaluate_script.
 *
 * Collects (26 categories):
 *   1. Vue Router routes (auto-bypass auth guards)
 *   2. React Router routes
 *   3. API paths (absolute URLs from source)
 *   4. API paths (relative paths)
 *   5. Domain names found in source
 *   6. IP addresses (v4)
 *   7. Email addresses
 *   8. Phone numbers (Chinese mobile)
 *   9. JWT tokens (eyJ... pattern)
 *  10. Credentials (password= / secret= / key= patterns)
 *  11. Cookie key-value pairs
 *  12. localStorage tokens
 *  13. sessionStorage tokens
 *  14. AK/SK cloud keys (AKIA/LTAI/AKID/AIza patterns)
 *  15. GitHub repo URLs
 *  16. Company/organization names
 *  17. Windows file paths
 *  18. URL query parameters
 *  19. HTML <script src> URLs
 *  20. WebSocket endpoints (ws:// wss://)
 *  21. Base64-encoded strings (potential secrets)
 *  22. JSON config objects in window scope
 *  23. JS file paths from webpack chunks
 *  24. Vue Store state (Pinia/Vuex) — v1.1 NEW
 *  25. Vue 3 setupState — v1.1 NEW
 *  26. Vue DevTools hook detection — v1.1 NEW
 *
 * Output: JSON object with all categories.
 */

(function() {
    'use strict';

    var results = {
        vue_routes: [],
        react_routes: [],
        api_paths_absolute: [],
        api_paths_relative: [],
        domains: [],
        ips: [],
        emails: [],
        phones: [],
        jwt_tokens: [],
        credentials: [],
        cookies: [],
        localStorage_tokens: [],
        sessionStorage_tokens: [],
        cloud_keys: [],
        github_links: [],
        company_names: [],
        windows_paths: [],
        url_params: [],
        script_srcs: [],
        ws_endpoints: [],
        base64_strings: [],
        window_configs: [],
        js_files: [],
        vue_store: {},          // v1.1: Pinia/Vuex store state
        vue_setup_state: {},    // v1.1: Vue 3 <script setup> setupState
        _meta: {
            url: window.location.href,
            title: document.title,
            has_vue: !!(window.__vue_app__ || window.__VUE__),
            has_react: !!(window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.getElementById('root')),
            has_angular: !!document.querySelector('[ng-app], [ng-version]'),
            has_jquery: !!window.jQuery,
            framework_version: '',
            devtools_exposed: false,  // v1.1
        }
    };

    // ── 1 & 2: Router routes ──

    try {
        // Vue 3
        if (window.__vue_app__) {
            var app = window.__vue_app__;
            if (app.config && app.config.globalProperties && app.config.globalProperties.$router) {
                var routes = app.config.globalProperties.$router.getRoutes();
                routes.forEach(function(r) {
                    results.vue_routes.push({
                        path: r.path,
                        name: r.name || '',
                        meta: r.meta || {},
                    });
                });
            }
            // Alternative: walk component tree
            if (app._instance && app._instance.proxy) {
                var proxy = app._instance.proxy;
                if (proxy.$router) {
                    var r2 = proxy.$router.getRoutes();
                    r2.forEach(function(r) {
                        var exists = results.vue_routes.some(function(e) { return e.path === r.path; });
                        if (!exists) {
                            results.vue_routes.push({
                                path: r.path,
                                name: r.name || '',
                                meta: r.meta || {},
                            });
                        }
                    });
                }
            }
        }

        // Vue 2
        if (window.__VUE__) {
            var apps = document.querySelectorAll('[id="app"], .app, [data-app]');
            apps.forEach(function(el) {
                if (el.__vue__ && el.__vue__.$router) {
                    el.__vue__.$router.options.routes.forEach(function(r) {
                        results.vue_routes.push({path: r.path, name: r.name || '', meta: r.meta || {}});
                    });
                }
            });
        }
    } catch(e) {
        results._meta.vue_error = e.message;
    }

    try {
        // React Router — look for __reactRouter or window.__INITIAL_STATE__
        if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
            results._meta.react_version = window.React ? window.React.version : 'unknown';
        }
        // Check for React Router v6 data
        var routerRoot = document.querySelector('[data-router]');
        if (routerRoot && routerRoot._reactRootContainer) {
            results._meta.react_router_detected = true;
        }
    } catch(e) {}

    // ── 3 & 4: API paths from script content ──

    try {
        var scripts = document.querySelectorAll('script');
        var allScriptContent = '';
        scripts.forEach(function(s) {
            if (s.src) {
                results.js_files.push(s.src);
            }
            if (s.textContent) {
                allScriptContent += s.textContent + '\n';
            }
        });

        // Absolute API URLs
        var absApiRe = /https?:\/\/[^\s"'<>]+?\/(?:api|v[12]|rest|graphql|internal|admin|manage)\/[^\s"'<>]*/gi;
        var absMatches = allScriptContent.match(absApiRe) || [];
        results.api_paths_absolute = Array.from(new Set(absMatches)).slice(0, 200);

        // Relative API paths
        var relApiRe = /['"\`](\/(?:api|v[12]|rest|graphql|internal|admin|manage|service)s?\/[^\s"'<>\{\}]*?)['"\`]/gi;
        var relMatches = [];
        var m;
        while ((m = relApiRe.exec(allScriptContent)) !== null) {
            relMatches.push(m[1]);
        }
        results.api_paths_relative = Array.from(new Set(relMatches)).slice(0, 200);
    } catch(e) {}

    // ── 5: Domains ──

    try {
        var domainRe = /https?:\/\/([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/gi;
        var domainMatches = allScriptContent.match(domainRe) || [];
        var domains = new Set();
        domainMatches.forEach(function(url) {
            try {
                var host = url.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
                if (host && host !== window.location.hostname && !host.includes('example.com')) {
                    domains.add(host);
                }
            } catch(e) {}
        });
        results.domains = Array.from(domains).slice(0, 100);
    } catch(e) {}

    // ── 6: IP addresses ──

    try {
        var ipRe = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
        results.ips = Array.from(new Set(allScriptContent.match(ipRe) || [])).slice(0, 50);
    } catch(e) {}

    // ── 7: Emails ──

    try {
        var emailRe = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
        results.emails = Array.from(new Set(allScriptContent.match(emailRe) || [])).slice(0, 50);
    } catch(e) {}

    // ── 8: Chinese phone numbers ──

    try {
        var phoneRe = /1[3-9]\d{9}/g;
        results.phones = Array.from(new Set(allScriptContent.match(phoneRe) || [])).slice(0, 30);
    } catch(e) {}

    // ── 9: JWT tokens ──

    try {
        var jwtRe = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g;
        results.jwt_tokens = Array.from(new Set(allScriptContent.match(jwtRe) || [])).slice(0, 20);
    } catch(e) {}

    // ── 10: Credentials ──

    try {
        var credPatterns = [
            /(?:password|passwd|pwd|secret|SECRET|secretKey|secret_key|SECRET_KEY)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
            /(?:apiKey|api_key|API_KEY|apikey|tokenKey)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
            /(?:JWT_SECRET|jwtSecret|jwt_secret)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
            /(?:SIGN_KEY|signKey|sign_key)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
        ];
        credPatterns.forEach(function(pattern) {
            var m;
            while ((m = pattern.exec(allScriptContent)) !== null) {
                results.credentials.push({
                    match: m[0].slice(0, 80),
                    value_preview: m[1] ? m[1].slice(0, 12) + '...' : '***',
                });
            }
        });
    } catch(e) {}

    // ── 11: Cookies ──

    try {
        document.cookie.split(';').forEach(function(c) {
            var parts = c.trim().split('=');
            if (parts.length >= 2) {
                results.cookies.push({
                    name: parts[0].trim(),
                    value_preview: parts.slice(1).join('=').trim().slice(0, 20),
                });
            }
        });
    } catch(e) {}

    // ── 12 & 13: localStorage & sessionStorage ──

    try {
        for (var i = 0; i < localStorage.length; i++) {
            var key = localStorage.key(i);
            var val = localStorage.getItem(key);
            if (key && val && (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth') || key.toLowerCase().includes('key') || key.toLowerCase().includes('secret'))) {
                results.localStorage_tokens.push({
                    key: key,
                    value_preview: val.slice(0, 30) + (val.length > 30 ? '...' : ''),
                    length: val.length,
                });
            }
        }
    } catch(e) {}
    try {
        for (var i = 0; i < sessionStorage.length; i++) {
            var key = sessionStorage.key(i);
            var val = sessionStorage.getItem(key);
            if (key && val && (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth'))) {
                results.sessionStorage_tokens.push({
                    key: key,
                    value_preview: val.slice(0, 30) + (val.length > 30 ? '...' : ''),
                    length: val.length,
                });
            }
        }
    } catch(e) {}

    // ── 14: Cloud keys ──
    // [...existing cloud key code...]

    // ── 14b: Vue Store state (Pinia/Vuex) — v1.1 ──
    try {
        // Pinia (Vue 3)
        if (window.__vue_app__ && window.__vue_app__.config && window.__vue_app__.config.globalProperties) {
            var pinia = window.__vue_app__.config.globalProperties.$pinia;
            if (pinia && pinia._s) {
                var stores = {};
                pinia._s.forEach(function(store, id) {
                    try {
                        var state = JSON.parse(JSON.stringify(store.$state));
                        // Filter to only high-value keys
                        var filtered = {};
                        var highValueKeys = /token|auth|user|role|permission|menu|route|config|admin|secret|password|key|api/;
                        Object.keys(state).forEach(function(k) {
                            if (highValueKeys.test(k) || k.length < 20) {
                                filtered[k] = state[k];
                            }
                        });
                        stores[id] = filtered;
                    } catch(e) {
                        stores[id] = { _error: e.message };
                    }
                });
                results.vue_store = { type: 'pinia', stores: stores };
            } else {
                // Vuex (Vue 2 or Vue 3 with Vuex)
                var store = window.__vue_app__.config.globalProperties.$store;
                if (!store) {
                    // Try __vue__ fallback
                    var appEl = document.querySelector('#app') || document.querySelector('[id="app"]');
                    if (appEl && appEl.__vue__ && appEl.__vue__.$store) {
                        store = appEl.__vue__.$store;
                    }
                }
                if (store && store.state) {
                    var vxState = {};
                    try {
                        Object.keys(store.state).forEach(function(mod) {
                            try {
                                vxState[mod] = JSON.parse(JSON.stringify(store.state[mod]));
                            } catch(e) { vxState[mod] = String(store.state[mod]).slice(0, 200); }
                        });
                    } catch(e) {}
                    var getters = [];
                    try { getters = Object.keys(store.getters || {}); } catch(e) {}
                    results.vue_store = { type: 'vuex', modules: Object.keys(store.state), getters: getters.slice(0, 30), state: vxState };
                }
            }
        }
        // Vue 2 standalone
        if (!results.vue_store.type && window.__VUE__) {
            var appEl = document.querySelector('#app');
            if (appEl && appEl.__vue__ && appEl.__vue__.$store) {
                var st = appEl.__vue__.$store;
                results.vue_store = { type: 'vuex', state_keys: Object.keys(st.state || {}), getters: Object.keys(st.getters || {}).slice(0, 30) };
            }
        }
    } catch(e) {
        results.vue_store._error = e.message;
    }

    // ── 14c: Vue 3 setupState — v1.1 ──
    try {
        if (window.__vue_app__ && window.__vue_app__._instance) {
            var setupState = window.__vue_app__._instance.setupState;
            if (setupState && Object.keys(setupState).length > 0) {
                var filtered = {};
                Object.keys(setupState).forEach(function(k) {
                    var val = setupState[k];
                    // Only capture strings (URLs, keys) and simple values
                    if (typeof val === 'string' && val.length < 500) {
                        filtered[k] = val;
                    } else if (typeof val === 'boolean' || typeof val === 'number') {
                        filtered[k] = val;
                    } else if (val && typeof val === 'object') {
                        filtered[k] = '[object ' + Object.keys(val).slice(0, 5).join(',') + ']';
                    }
                });
                results.vue_setup_state = filtered;
            }
        }
    } catch(e) {
        results.vue_setup_state._error = e.message;
    }

    try {
        var akPatterns = [
            /AKIA[0-9A-Z]{16}/g,      // AWS Access Key
            /AKID[0-9A-Za-z]{32}/g,    // Tencent Cloud SecretId
            /LTAI[0-9A-Za-z]{20}/g,    // Alibaba Cloud AccessKey
            /AIza[0-9A-Za-z_-]{35}/g,  // Google API Key
            /APID[0-9A-Za-z]{32}/g,    // Another cloud key pattern
        ];
        akPatterns.forEach(function(pattern) {
            var m;
            while ((m = pattern.exec(allScriptContent)) !== null) {
                results.cloud_keys.push({key: m[0], type: m[0].slice(0, 4)});
            }
        });
        results.cloud_keys = results.cloud_keys.slice(0, 20);
    } catch(e) {}

    // ── 15: GitHub links ──

    try {
        var ghRe = /https?:\/\/github\.com\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+/gi;
        results.github_links = Array.from(new Set(allScriptContent.match(ghRe) || [])).slice(0, 20);
    } catch(e) {}

    // ── 16: Company names ──

    try {
        var companyPatterns = [
            /(?:company|corp|organization|orgName|org_name|companyName|company_name)\s*[:=]\s*['"]([^'"]{2,50})['"]/gi,
        ];
        companyPatterns.forEach(function(pattern) {
            var m;
            while ((m = pattern.exec(allScriptContent)) !== null) {
                if (m[1] && m[1].length > 1) {
                    results.company_names.push(m[1]);
                }
            }
        });
        results.company_names = Array.from(new Set(results.company_names)).slice(0, 10);
    } catch(e) {}

    // ── 17: Windows paths ──

    try {
        var winPathRe = /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g;
        results.windows_paths = Array.from(new Set(allScriptContent.match(winPathRe) || [])).slice(0, 30);
    } catch(e) {}

    // ── 18: URL query parameters ──

    try {
        var params = new URLSearchParams(window.location.search);
        var paramList = [];
        params.forEach(function(v, k) { paramList.push({key: k, value: v}); });
        results.url_params = paramList;
    } catch(e) {}

    // ── 19: Script src URLs ──

    results.script_srcs = results.js_files.slice();

    // ── 20: WebSocket endpoints ──

    try {
        var wsRe = /(?:ws|wss):\/\/[^\s"'<>]+/gi;
        results.ws_endpoints = Array.from(new Set(allScriptContent.match(wsRe) || [])).slice(0, 20);

        // Also check for new WebSocket( patterns
        var wsConstructorRe = /new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]/gi;
        var wsConMatches = [];
        var m;
        while ((m = wsConstructorRe.exec(allScriptContent)) !== null) {
            wsConMatches.push(m[1]);
        }
        wsConMatches.forEach(function(url) {
            if (!results.ws_endpoints.includes(url)) {
                results.ws_endpoints.push(url);
            }
        });
    } catch(e) {}

    // ── 21: Long base64 strings ──

    try {
        var b64Re = /[A-Za-z0-9+/=]{40,}/g;
        var b64Matches = (allScriptContent.match(b64Re) || [])
            .filter(function(s) { return s.length > 40 && s.length < 500; });
        results.base64_strings = Array.from(new Set(b64Matches)).slice(0, 20);
    } catch(e) {}

    // ── 22: Window configs ──

    try {
        var configKeys = ['__CONFIG__', '__APP_CONFIG__', '__RUNTIME_CONFIG__',
                         '__INITIAL_STATE__', '__NUXT__', '__NEXT_DATA__',
                         '_env_', 'APP_CONFIG', 'CONFIG', 'env'];
        configKeys.forEach(function(k) {
            if (window[k] !== undefined) {
                try {
                    results.window_configs.push({
                        key: k,
                        type: typeof window[k],
                        keys_preview: typeof window[k] === 'object' ?
                            Object.keys(window[k]).slice(0, 20).join(', ') :
                            String(window[k]).slice(0, 100),
                    });
                } catch(e) {
                    results.window_configs.push({key: k, type: typeof window[k], error: String(e)});
                }
            }
        });
    } catch(e) {}

    // ── 23: Framework version ──

    try {
        if (window.__vue_app__) {
            results._meta.framework_version = 'Vue ' + (window.Vue ? window.Vue.version : '3.x');
        } else if (window.__VUE__) {
            results._meta.framework_version = 'Vue ' + (window.Vue ? window.Vue.version : '2.x');
        } else if (window.React) {
            results._meta.framework_version = 'React ' + window.React.version;
        } else if (window.angular) {
            results._meta.framework_version = 'Angular ' + (window.angular.version ? window.angular.version.full : '');
        }
    } catch(e) {}

    // ── 23b: Vue DevTools hook detection — v1.1 ──
    try {
        if (typeof window.__VUE_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined') {
            results._meta.devtools_exposed = true;
            if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue && window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue.version) {
                results._meta.framework_version = results._meta.framework_version ||
                    'Vue ' + window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue.version;
            }
            // Count active apps
            if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__.apps) {
                results._meta.vue_app_count = window.__VUE_DEVTOOLS_GLOBAL_HOOK__.apps.length;
            }
        }
    } catch(e) {}

    return JSON.stringify(results, null, 2);
})();
