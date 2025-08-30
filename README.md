# 描述
这是一个**purevpn自动获取/刷新/保活wireguard配置**的python脚本，由于purevpn使用wireguard配置居然要额外收费，于是产生了此脚本

不保证接口变动后的可用性，在仓库上传的时候是可用的

默认为香港区域，需要其他区域请自行查看 `region.json` 修改环境变量 `PUREVPN_COUNTRY_SLUG` 和 `PUREVPN_CITY_ID`

若遇到无法获取的情况，有可能是ip太脏触发了cloudflare的风控

需要每隔15分钟启动一次脚本配置保活，wireguard配置一般不变（因为私钥公钥都不变）

# 用法示例
```bash
git clone https://github.com/twoonefour/purevpn-wg-auto-conf.git
cd purevpn-wg-auto-conf
pip install -r requirements.txt
export PUREVPN_USERNAME=xxx@example.com # 写你的purevpn登陆账号
export PUREVPN_PASSWORD=xxxxx # 你的purevpn登陆密码
python main.py
```

# 输出示例
```
[ok] 登录成功，fa_token 已入会话。
[ok] 取到加密密码（长度 24）。
[ok] Address 提取成功： 172.21.7.x
[ok] wireguard私钥为： qaqqaqYoHgXxdvP6QzQSpGeJxng=
[OK] 完整配置为
 [Interface]
PrivateKey=6DRFW9GXH7Qqaq+YoHgXxdvP6QzQSpGeJxng=
Address=172.21.7.x
DNS=103.109.x.x,103.109.x.x
[Peer]
PublicKey=Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8=
AllowedIPs=0.0.0.0/0
Endpoint=qaq.com:51820
PersistentKeepalive=21

进程已结束，退出代码为 0

```

可自行使用wireguard配置

# 程序环境变量
| 名称               | 说明         | 必须项 |
|------------------|------------|-----|
| PUREVPN_USERNAME | purevpn的账号 | 是   |
| PUREVPN_PASSWORD | purevpn的密码 | 是   |
|PUREVPN_COUNTRY_SLUG| vpn地区      | 否   |
|     PUREVPN_CITY_ID             | VPN地区代号    | 否   |


# 声明
本脚本是爬虫项目，请自行承担有可能来自purevpn的封号风险

若purevpn方认为此脚本侵权，请联系我`emailto:twoonefour@voidval.com`删除
