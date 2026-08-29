from playwright.sync_api import sync_playwright
import json, time, base64, sys
import ddddocr
ocr = ddddocr.DdddOcr(show_ad=False)
ACCOUNT = sys.argv[1] if len(sys.argv)>1 else "2568285028"
PASSWORD = sys.argv[2] if len(sys.argv)>2 else "u6Lgzst."

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    xhrs = []
    def on_resp(resp):
        if resp.request.resource_type in ("xhr","fetch"):
            try:
                xhrs.append({"status": resp.status, "url": resp.url[:200]})
            except Exception: pass
    page.on("response", on_resp)
    try:
        page.goto('https://exhibitor.cantonfair.org.cn/#/agentLogin', wait_until='domcontentloaded', timeout=60000)
    except Exception:
        pass
    page.wait_for_timeout(8000)
    # fill inputs
    page.evaluate("""([acct, pwd]) => {
        const ins=[...document.querySelectorAll('input')];
        const setv=(el,v)=>{const setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;setter.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};
        if(ins[0]) setv(ins[0], acct);
        if(ins[1]) setv(ins[1], pwd);
    }""", [ACCOUNT, PASSWORD])
    page.wait_for_timeout(1000)
    # get captcha
    page.evaluate("""async () => {
        const app=document.querySelector('#app'); let lv=null;
        function w(vm,d){ if(!vm||d>10||lv)return; if(vm.slideStatus!==undefined&&vm.signIn)lv=vm; if(vm.$children)vm.$children.forEach(c=>w(c,d+1)); }
        w(app.__vue__,0);
        if(!lv) return;
        await lv.getverifyCodeImg().then(r=>{ lv.codeImg=r.verifyCodeImg; lv.uuId=r.verifyUUID; });
    }""")
    imgb64 = page.evaluate("""() => { const app=document.querySelector('#app'); let lv=null; function w(vm,d){ if(!vm||d>10||lv)return; if(vm.slideStatus!==undefined&&vm.signIn)lv=vm; if(vm.$children)vm.$children.forEach(c=>w(c,d+1)); } w(app.__vue__,0); return lv?lv.codeImg:''; }""")
    code = ''
    if imgb64:
        try:
            code = ''.join(ch for ch in ocr.classification(base64.b64decode(imgb64)) if ch.isalnum())
        except Exception as e:
            code = ''
    print("OCR code:", repr(code))
    if len(code)!=4: code=code[:4].ljust(4,'x')
    page.evaluate("""(code) => {
        const app=document.querySelector('#app'); let lv=null;
        function w(vm,d){ if(!vm||d>10||lv)return; if(vm.slideStatus!==undefined&&vm.signIn)lv=vm; if(vm.$children)vm.$children.forEach(c=>w(c,d+1)); }
        w(app.__vue__,0);
        if(!lv) return;
        lv.view.model.verifyCodeImg=code; lv.picCode=code;
        const cb=[...document.querySelectorAll('input')].find(i=>i.type==='checkbox');
        if(cb && !cb.checked){ cb.click(); }
        lv.agreementChecked=true;
    }""", code)
    page.wait_for_timeout(300)
    page.evaluate("""() => {
        const app=document.querySelector('#app'); let sv=null;
        function w(vm,d){ if(!vm||d>8)return; if(vm.$options&&vm.$options.name==='slideVerifyPlugin')sv=vm; if(vm.$children)vm.$children.forEach(c=>w(c,d+1)); }
        w(app.__vue__,0);
        if(sv){ sv.msg=1; sv.outerVisible=false; sv.$emit('getSlideStatus',1); }
    }""")
    page.wait_for_timeout(3500)
    page.evaluate("""() => { const btn=[...document.querySelectorAll('button')].find(b=>b.innerText.trim()==='Login'); if(btn) btn.click(); }""")
    page.wait_for_timeout(12000)
    info = page.evaluate("""() => {
        const out = {};
        try {
            const app=document.querySelector('#app'); const store=app.__vue__.$store;
            out.vuex_state_keys = Object.keys(store.state);
            for (const k of Object.keys(store.getters)) {
                let v; try { v = store.getters[k]; } catch(e){ v = 'ERR:'+String(e); }
                if (v && typeof v === 'object') { try { v = JSON.stringify(v); } catch(e){} }
                out['getter_'+k] = String(v).slice(0, 2000);
            }
        } catch(e){ out.vuex_err = String(e); }
        const ls = {};
        for (const k in localStorage) {
            let key=k; try{key=atob(k);}catch(e){}
            ls[key] = String(localStorage[k]).slice(0, 200);
        }
        out.localStorage = ls;
        const ss = {};
        for (const k in sessionStorage) {
            let key=k; try{key=atob(k);}catch(e){}
            try { ss[key] = String(sessionStorage[k]).slice(0, 200); } catch(e){ ss[key]='<nonstr>'; }
        }
        out.sessionStorage = ss;
        out.location = location.href;
        return JSON.stringify(out);
    }""")
    print("===STORE===")
    print(info)
    print("===XHRS===")
    for x in xhrs:
        print(x['status'], x['url'])
    browser.close()
