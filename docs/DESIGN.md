# 设计说明：为什么是插件，为什么要包路由表

> 这篇讲实现和取舍。使用看 [README](../README.md)。

---

## 一、问题：DSH 没有「人」这一层

DSH 的 Web 入口自带的是**进程级 launch token**：

```
dsh web: http://127.0.0.1:3080/?token=<每次启动随机生成>
```

- 拿到 URL 的人就能进
- token 在进程内存里，不落盘、不可找回
- 它更像 CSRF/session 绑定，不是「证明你是主人」

一旦把 3080 暴露到公网（内网穿透、反代、隧道），任何拿到 URL 的人都能用你的算力、看你的会话。

---

## 二、约束：没有中间件

DSH 的 HTTP 服务（`@deepseek-ai/dsh-host-webserver`）是这样分发请求的：

```js
handle(req, res) {
  const route = this.match(pathname);
  if (route) return route.handler(req, res);
  if (this.fallback) return this.fallback(req, res);
  return 404;
}
```

扩展点只有四个：

| 扩展点 | 能力 |
|---|---|
| `register({ kind: 'exact', path, handler })` | 占一个精确路径，重复会抛错 |
| `register({ kind: 'prefix', path, handler })` | 占一个路径前缀 |
| `registerUpgrade({ path, handler })` | 占一个 WebSocket 升级路径 |
| `registerFallback(handler)` | 兜底，**只能有一个**，已被 SPA 占用 |

**没有 `use(middleware)`。**

所以官方扩展点做不到「所有请求先过一道」。只能**包**：把已注册的 handler 换成包装函数，在调用原函数之前做鉴权。

---

## 三、方案：包住路由表

插件拿到 `ctx.webServer` 后，对三张表和兜底做原地包装：

```js
for (const [k, r] of ws.exact)    ws.exact.set(k, { ...r, handler: wrap(r.handler) });
for (const [k, r] of ws.prefixes) ws.prefixes.set(k, { ...r, handler: wrap(r.handler) });
for (const [k, r] of ws.upgrades) ws.upgrades.set(k, { ...r, handler: wrapUp(r.handler) });
if (ws.fallback) ws.fallback = wrap(ws.fallback);

// 之后注册的也要包
ws.register = (route) => origRegister({ ...route, handler: wrap(route.handler) });
```

包装函数做的事：

```
请求进来
  ├─ /__auth/*   → 自己处理（设置 / 登录 / 忘记密码 / 健康检查）
  ├─ 还没设密码   → 本机：302 设置页；外网：503 提示
  ├─ 未登录       → HTML: 302 登录页 / API: 401
  └─ 已登录       → 补 DSH cookie 和 Host，再交给原 handler
```

### 为什么要「补 DSH 的 cookie」

DSH 自己还要校验一轮（`BrowserAuth`）。不想让浏览器持有 DSH 的内部凭据，所以**由插件代签**：

```js
// 用 ~/.dsh/.credentials.yaml 里的 browser-session secret
payload = { version: 1, authority, issuedAt, expiresAt }
value   = 'v1.' + b64url(payload) + '.' + b64url(HMAC(secret, body))
```

同时把 `Host` / `Origin` 重写成监听地址（`127.0.0.1:3080`），否则 DSH 的 Host/Origin fence 会拒绝外部域名。

**结果**：浏览器只认识插件发的 `dsh_gate` cookie，DSH 的内部凭据对它完全不可见。

---

## 四、密码怎么存

```
%USERPROFILE%\.dsh\auth-gate.dat
```

内容 = **DPAPI 加密**后的 JSON：

```json
{ "v": 1, "hash": "<scrypt(password)>", "salt": "<random 16B>", "secret": "<session HMAC key>" }
```

| 设计 | 原因 |
|---|---|
| 只存 scrypt 派生值 | 文件泄露也拿不到原密码 |
| scrypt N=16384, r=8, p=1 | 抗暴力破解，单次约 100ms |
| DPAPI 绑定当前 Windows 用户 | 拷到别的机器/账户解不开 |
| 会话密钥放同一文件 | 改密码 = 换密钥 = 所有设备下线 |
| 时间常数比较 | 防时序侧信道 |

---

## 五、安全属性

| 攻击面 | 处理 |
|---|---|
| 密码爆破 | 每 IP 连续 5 次失败锁 10 分钟（识别 `CF-Connecting-IP`） |
| 伪造会话 | HMAC-SHA256 + 过期时间，签名不符直接拒绝 |
| 绕过登录 | 所有路由（含 fallback、WS 升级）都被包装，没有未包装的入口 |
| 公网抢注密码 | 初始化只允许 loopback（无转发头的 127.0.0.1） |
| 会话被截获 | cookie `HttpOnly` + `SameSite=Lax`；HTTPS 下自动 `Secure` |
| 登录页被嵌入 | `X-Frame-Options: DENY` |
| 缓存泄露 | 认证响应统一 `Cache-Control: no-store` |

---

## 六、测试

`npm test` 用 mock 的 `webServer` 起真实 HTTP 服务，跑 **24 个用例**：

```
首次初始化 6 项：跳转、设置页、短密码、两次不一致、外网禁止、成功自动登录
登录后      3 项：进首页、Host 重写、DSH cookie 注入
未登录      2 项：HTML 302、API 401
页面与帮助  6 项：登录页、显示密码按钮、忘记密码入口、PowerShell/cmd/绝对路径
密码校验    3 项：错误密码、正确密码、伪造 cookie
其它        2 项：健康检查、限流 429
```

另外在真实 DSH 实例（独立 profile + 3090 端口）做过端到端验证。

---

## 七、一次真实的 UX 返工

最初的实现里，没设密码时页面只吐一句：

> 未设置密码，先运行 `node setup.mjs` 设置访问密码。

用户反馈（原话）：

> 这个很难用。没有提示啥也没有。我也是摸索一会才知道咋用的。你要不要设置个页面……如果忘记密码了要怎么操作。

于是重做了三件事：

1. **设置页**：直接在当前页面输入两次密码，插件自己调 `writeState()`（和 `setup.mjs` 同一套逻辑）
2. **显示密码**：输入框右侧「显示」，避免打错
3. **忘记密码页**：给出本机绝对路径 + PowerShell / cmd / 资源管理器三种方式

教训：**把 CLI 步骤搬到网页里，不是"以后再说"的优化，而是第一次就要想清楚的事。**

---

## 八、已知边界

| 边界 | 后果 | 应对 |
|---|---|---|
| 依赖 `webServer.exact/prefixes/upgrades/fallback` 字段名 | DSH 升级改名后**静默失效** | 升级后跑 `npm test` + 冒烟 |
| 依赖 `.credentials.yaml` 的 secret 格式 | DSH 换 cookie 格式需同步 | 同上 |
| 限流是进程内内存 | 重启清零 | 可接受 |
| 安装后需要重启 | 不是热加载 | 文档已写明 |
| 仅 Windows | DPAPI | 其他平台需换存储层 |

---

## 九、和前置代理方案对比

在插件之前还写过一个独立代理（监听另一个端口）。两者都能用：

| | 插件 | 前置代理 |
|---|---|---|
| 端口 | 不额外占 | 多一个 |
| 部署 | 进程内，重启生效 | 独立进程，随时起停 |
| 依赖 | DSH 内部字段 | 只需 cookie 格式 |
| 适用 | 长期、干净 | 临时、隔离 |

插件生效后代理可以退役：把隧道目标改回 3080 即可。
