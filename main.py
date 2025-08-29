# @Time    : 2025/8/29 15:35
# @Author  : TwoOnefour
# @blog    : https://www.voidval.com
# @Email   : twoonefour@voidval.com
# @File    : main.py
import os
import re
import json
import typing as t
from curl_cffi import requests
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

AUTH_BASE = "https://auth.purevpn.com"
APP_BASE = "https://my.purevpn.com"

CLIENT_ID = "ed1ee674-0a34-4265-b4a1-141b721036eb"
TENANT_ID = "9707f41e-21a4-bbc5-dcbc-fdf6b61cc68f"
REDIRECT_URI = f"{APP_BASE}/v2/api/fusionauth/login"
TIMEOUT = 30

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"
)


class PureVPNClient:
    def __init__(self):
        self.s: requests.Session = requests.Session(impersonate='chrome116')
        # self.s.proxies = {"https": "http://127.0.0.1:9099"}
        # self.s.verify = False
        self.s.headers.update({
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en",
        })
        self.fa_token: t.Optional[str] = None
        self.VPNUSERNAME = None
        self.SUBS_ID = None

    def setFaToken(self, token: str):
        self.s.cookies.set("fa_token", token)

    # ---------- 工具 ----------
    @staticmethod
    def _b64url_json(segment: str) -> dict:
        pad = "=" * (-len(segment) % 4)
        data = base64.urlsafe_b64decode(segment + pad)
        return json.loads(data.decode("utf-8", "ignore"))

    @staticmethod
    def _extract_address_from_wg_config(cfg: str) -> str:
        """
        从 wireguard_configuration 字符串中提取 Address=... 的值，返回右侧的原样字符串。
        例如 '172.21.6.133' 或 '10.14.0.3/32, fd00:.../128'
        """
        # 优先精确匹配整行
        m = re.search(r'(?im)^\s*Address\s*=\s*(.+?)\s*$', cfg)
        if not m:
            raise ValueError("Address not found in wireguard_configuration")
        return m.group(1).strip()

    def login(self, login_id: str, password: str, timezone: str = "Asia/Hong_Kong", fa_token: str = None) -> str:
        # 预热：拿 CSRF / SSO 等初始 Cookie
        self.s.get(AUTH_BASE + "/oauth2/authorize", params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
        }, timeout=TIMEOUT)

        # 按抓包表单字段构造
        form = {
            "captcha_token": "",
            "client_id": CLIENT_ID,
            "code_challenge": "",
            "code_challenge_method": "",
            "metaData.device.name": "Windows Chrome",
            "metaData.device.type": "BROWSER",
            "nonce": "",
            "pendingIdPLinkId": "",
            "redirect_uri": REDIRECT_URI,
            "response_mode": "",
            "response_type": "code",
            "scope": "",
            "state": "",
            "tenantId": TENANT_ID,
            "timezone": timezone,
            "user_code": "",
            "showPasswordField": "true",
            "loginId": login_id,
            "password": password,
        }

        headers = {
            "Origin": AUTH_BASE,
            "Referer": AUTH_BASE + "/",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if fa_token and self.check_fa_token(fa_token):
            self.setFaToken(fa_token)
            self.fa_token = fa_token
            self.s.headers.update({
                "Authorization": f"Bearer {fa_token}",
                "Accept": "application/json",
            })
            return fa_token
        # 这一步会 302 多次直到 my.purevpn.com 下发 fa_token；允许自动跟随
        r = self.s.post(AUTH_BASE + "/oauth2/authorize", data=form,
                        headers=headers, timeout=TIMEOUT, allow_redirects=True)
        r.raise_for_status()

        # 从 Session 里取 fa_token（Set-Cookie: fa_token=...; domain=.purevpn.com）
        fa_token = None
        for k in self.s.cookies.get_dict():
            if k == "fa_token":
                fa_token = self.s.cookies[k]
                break

        if not fa_token:
            raise RuntimeError("登录后没有拿到 fa_token（可能被验证码/风控拦截，或凭据错误）")

        self.fa_token = fa_token
        self.s.headers.update({
            "Authorization": f"Bearer {fa_token}",
            "Accept": "application/json",
        })
        self.check_fa_token(fa_token)
        return fa_token

    def check_fa_token(self, fa_token: str) -> bool:
        url = f"{APP_BASE}/v2/api/on-boarding"
        self.s.headers.update({
            "Authorization": f"Bearer {fa_token}",
        })
        try:
            resp = self.s.post(url)
        except Exception as e:
            return False
        if resp.headers.get("content-type") == "application/json" and resp.status_code == 200 and resp.json().get(
                "status") == True:
            self.SUBS_ID = resp.json()["body"]["subscriptions"][0]["id"]
            self.VPNUSERNAME = resp.json()["body"]["subscriptions"][0]["vpnusernames"][0]
            return True
        return False

    def get_encrypted_password(self, vpn_username: str) -> dict:
        url = APP_BASE + "/v2/api/wireguard/get-encrypt-password"
        headers = {
            "Origin": APP_BASE,
            "Referer": APP_BASE + "/v2/dashboard/manual-config",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        r = self.s.post(url, data={"username": vpn_username},
                        headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        j = r.json()
        if not j.get("status"):
            raise RuntimeError(f"get-encrypt-password 失败: {j}")
        return j["body"]  # {username,password,encrypPass}

    def get_wg_config_and_address(
            self,
            vpn_username: str,
            encrypted_password: str,
            *,
            country_slug: str = "HK",
            device_type: str = "linux",
            client_public_key: str,
            client_private_key: t.Optional[str] = None,
            city_id: t.Optional[int] = None,
            subs_id: t.Optional[str] = None,
            nat_server: bool = True,
    ) -> t.Tuple[str, str, dict]:
        url = APP_BASE + "/v2/api/wireguard/get-wg-server"
        form = {
            "sUsername": vpn_username,
            "sPassword": encrypted_password,
            "sCountrySlug": country_slug,
            "sDeviceType": device_type,
            "sClientPublicKey": client_public_key,
            "natServer": "1" if nat_server else "0",
        }
        if city_id is not None:
            form["iCityId"] = str(city_id)
        if subs_id is not None:
            form["sSubsId"] = subs_id

        headers = {
            "Origin": APP_BASE,
            "Referer": APP_BASE + "/v2/dashboard/manual-config",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        r = self.s.post(url, data=form, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        j = r.json()
        if not j.get("status"):
            raise RuntimeError(f"get-wg-server 失败: {j}")

        body = j.get("body")
        if isinstance(body, list) and body:
            cfg = body[0].get("wireguard_configuration", "")
        elif isinstance(body, dict):
            cfg = body.get("wireguard_configuration", "")
        else:
            cfg = ""
        if not cfg:
            raise RuntimeError("响应中未发现 wireguard_configuration")

        # 如需补上你本地的私钥
        if client_private_key:
            cfg = cfg.replace("{clientPrivateKey}", client_private_key)

        address = self._extract_address_from_wg_config(cfg)
        return address, cfg, j


if __name__ == "__main__":
    LOGIN_ID = os.getenv("PUREVPN_USERNAME") # 填入账号
    PASSWORD = os.getenv("PUREVPN_PASSWORD") # 填入密码

    if not os.path.exists("CLIENT_PRIVATE_KEY"):
        sk = X25519PrivateKey.generate()
        CLIENT_PRIVATE_KEY = base64.b64encode(sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
        CLIENT_PUBLIC_KEY = base64.b64encode(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        with open("CLIENT_PRIVATE_KEY", "w") as f:
            f.write(CLIENT_PRIVATE_KEY)
            f.write("\n")
            f.write(CLIENT_PUBLIC_KEY)
    else:
        with open("CLIENT_PRIVATE_KEY", "r") as f:
            CLIENT_PRIVATE_KEY = f.readline().strip()
            CLIENT_PUBLIC_KEY = f.readline().strip()

    # 可选：你已知的 VPN 用户名、订阅 id、城市/国家
    CITY_ID = int(os.getenv("PUREVPN_CITY_ID", "4300"))  # 例如 4300
    COUNTRY_SLUG = os.getenv("PUREVPN_COUNTRY_SLUG", "HK")  # 例如 HK
    DEVICE_TYPE = "linux"

    client = PureVPNClient()

    if os.path.exists("fa_token"):
        with open("fa_token", "r") as f:
            fa_token = f.read().strip()
            client.login(LOGIN_ID, PASSWORD, fa_token=fa_token)
    else:
        fa_token = client.login(LOGIN_ID, PASSWORD)

    print("[ok] 登录成功，fa_token 已入会话。")
    with open("fa_token", "w") as f:
        f.write(fa_token)

    enc_info = client.get_encrypted_password(client.VPNUSERNAME)
    encryp_pass = enc_info["encrypPass"]
    print(f"[ok] 取到加密密码（长度 {len(encryp_pass)}）。")

    address, wg_conf, full_json = client.get_wg_config_and_address(
        vpn_username=client.VPNUSERNAME,
        encrypted_password=encryp_pass,
        country_slug=COUNTRY_SLUG,
        device_type=DEVICE_TYPE,
        client_public_key=CLIENT_PUBLIC_KEY,
        client_private_key=CLIENT_PRIVATE_KEY,
        city_id=CITY_ID,
        subs_id=client.SUBS_ID,
        nat_server=True,
    )

    print("[ok] Address 提取成功：", address)
    print("[ok] wireguard私钥为：", CLIENT_PRIVATE_KEY)
    print("[OK] 完整配置为\n", wg_conf)