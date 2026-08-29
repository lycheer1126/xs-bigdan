from playwright.sync_api import sync_playwright
import json, time, base64
import ddddocr
ocr = ddddocr.DdddOcr(show_ad=False)
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    try:
        page.goto('https://exhibitor.cantonfair.org.cn/#/agentLogin', wait_until='domcontentloaded', timeout=60000)
    except Exception:
        pass
    page.wait_for_timeout(8000)
    page.evaluate("""() => {
        const ins=[...document.querySelectorAll('input')];
        const setv=(el,v)=>{const setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;setter.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};
        setv(ins[0],'2568285028'); setv(ins[1],'u6Lgzst.');
    }""")
    page.wait_for_timeout(1200)
    page.evaluate("""async () => {
        const app=document.querySelector('#app'); let lv=null;
        function w(vm,d){ if(!vm||d>10||lv)return; if(vm.slideStatus!==undefined&&vm.signIn)lv=vm; if(vm.$children)vm.$children.forEach(c=>w(c,d+1)); }
        w(app.__vue__,0);
        await lv.getverifyCodeImg().then(r=>{ lv.codeImg=r.verifyCodeImg; lv.uuId=r.verifyUUID; });
    }""")
    imgb64 = page.evaluate("""() => { const app=document.querySelector('#app'); let lv=null; function w(vm,d){ if(!vm||d>10||lv)return; if(vm.slideStatus!==undefined&&vm.signIn)lv=vm; if(vm.$children)vm.$children.forEach(c=>w(c,d+1)); } w(app.__vue__,0); return lv?lv.codeImg:''; }""")
    code = ''.join(ch for ch in ocr.classification(base64.b64decode(imgb64)) if ch.isalnum())
    if len(code)!=4: code=code[:4].ljust(4,'x')
    page.evaluate("""(code) => {
        const app=document.querySelector('#app'); let lv=null;
        function w(vm,d){ if(!vm||d>10||lv)return; if(vm.slideStatus!==undefined&&vm.signIn)lv=vm; if(vm.$children)vm.$children.forEach(c=>w(c,d+1)); }
        w(app.__vue__,0);
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
    tok = page.evaluate("""() => {
        const ls={...localStorage};
        const out={};
        for (const k in ls) {
            let key=k; try { key=atob(k); } catch(e){}
            if(/token/i.test(key)) out[key]=ls[k];
        }
        // also vuex store token
        try { const app=document.querySelector('#app'); out['vuex_token']=app.__vue__.$store.getters.token; } catch(e){}
        return JSON.stringify(out);
    }""")
    print("TOKENS:", tok)
    browser.close()
