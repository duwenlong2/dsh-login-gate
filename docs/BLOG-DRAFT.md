# 给 DSH 加一道登录门：一个插件，24 项测试

> 上一篇在折腾 Agent 的工具和记忆。这篇换个方向：**DSH 本身怎么安全地暴露到公网**。
> 起因很简单——我把 DSH 挂到了内网穿透上，然后意识到：**谁知道那个网址，谁就能用我的机器。**
> 这篇记录整个过程：为什么不能加中间件、最后怎么绕过去、以及第一版被用户骂回来之后的重做。

## 关于 dsh-login-gate 开源项目

这是配套这个插件的开源仓库 [**dsh-login-gate**](https://github.com/duwenlong2/dsh-login-gate)（MIT）：

```
dsh-login-gate/
├─ index.js          ← cordis 插件：包装 DSH 的路由表
├─ gate.js           ← 门禁核心：会话 / 密码 / 页面 / 限流
├─ dpapi.js          ← Windows DPAPI 封装
├─ test/harness.mjs  ← 24 项隔离测试
└─ docs/
   ├─ DESIGN.md      ← 实现与取舍（本文的详细版）
   └─ images/        ← 截图
```

**推荐阅读方式**：

1. 看这篇建立概念
2. 打开 `test/harness.mjs` 跑一遍 `npm test`，看 24 项断言
3. 想改：看 `gate.js` 的 `createGate()`，所有逻辑都在里面

## 一、先说结论

给 DSH 加登录，**不需要改 DSH 源码**，也不需要多开一个代理端口。
一个插件 + 三个文件，在进程内把请求拦下来：

```
浏览器 ──▶ DSH :3080 ──▶ [dsh-login-gate] ──▶ Harness
                              │
                              ├─ 未登录：302 登录页（HTML）/ 401（API）
                              └─ 已登录：补 DSH cookie + 重写 Host → 原 handler
```

## 二、问题：DSH 只有 launch token

DSH 启动时会打印这样一个地址：

```
dsh web: http://127.0.0.1:3080/?token=39TFonttqpxF6lU8e0NcdbvTAGFRhfjK8SHbS4T2cS4
```

这个 token：

- 每次启动随机生成
- 存在进程内存里，不落盘、不可找回
- 作用更像 CSRF/session 绑定，**不是"证明你是主人"**

所以一旦把 3080 暴露出去，**拿到 URL 的人就能用你的算力、看你的会话**。

## 三、为什么不能加中间件

先看 DSH 的 HTTP 服务（`@deepseek-ai/dsh-host-webserver`）怎么分发请求：

```js
handle(req, res) {
  const route = this.match(pathname);
  if (route) return route.handler(req, res);
  if (this.fallback) return this.fallback(req, res);
  return 404;
}
```

它的扩展点只有四个：

| 扩展点 | 能力 |
|---|---|
| `register({kind:'exact'})` | 占一个精确路径，重复会抛错 |
| `register({kind:'prefix'})` | 占一个路径前缀 |
| `registerUpgrade()` | 占一个 WebSocket 升级路径 |
| `registerFallback()` | 兜底，**只能有一个**，已被 SPA 占用 |

**没有 `use(middleware)`。**

结论：官方扩展点做不到"所有请求先过一道"，只能**包**。

## 四、方案：包住路由表

`webServer` 服务的三张表就是普通 `Map`，插件在激活时把它们原地换掉：

```js
for (const [k, r] of ws.exact)    ws.exact.set(k, { ...r, handler: wrap(r.handler) });
for (const [k, r] of ws.prefixes) ws.prefixes.set(k, { ...r, handler: wrap(r.handler) });
for (const [k, r] of ws.upgrades) ws.upgrades.set(k, { ...r, handler: wrapUp(r.handler) });
if (ws.fallback) ws.fallback = wrap(ws.fallback);

// 之后注册的路由也要包
ws.register = (route) => origRegister({ ...route, handler: wrap(route.handler) });
```

包装函数的分支：

```
请求进来
  ├─ /__auth/*   → 自己处理（设置 / 登录 / 忘记密码 / 健康检查）
  ├─ 还没设密码   → 本机：302 设置页；外网：503
  ├─ 未登录       → HTML: 302 登录页 / API: 401
  └─ 已登录       → 补 DSH cookie 和 Host，再交给原 handler
```

### 关键一环：代签 DSH 的 cookie

DSH 自己还要校验一轮。我不想让浏览器持有 DSH 的内部凭据，所以**由插件代签**：

```js
// 用 ~/.dsh/.credentials.yaml 里的 browser-session secret
payload = { version: 1, authority, issuedAt, expiresAt }
value   = 'v1.' + b64url(payload) + '.' + b64url(HMAC(secret, body))
```

同时把 `Host` / `Origin` 重写成 `127.0.0.1:3080`，否则 DSH 的 Host/Origin fence 会拒绝外部域名。

**浏览器只认识插件发的 `dsh_gate` cookie，DSH 的内部凭据对它不可见。**

## 五、密码放哪：DPAPI + scrypt

```
%USERPROFILE%\.dsh\auth-gate.dat
```

内容 = **DPAPI 加密**后的 JSON：

```json
{ "v": 1, "hash": "<scrypt(password)>", "salt": "<随机 16 字节>", "secret": "<会话 HMAC 密钥>" }
```

| 设计 | 原因 |
|---|---|
| 只存 scrypt 派生值 | 文件泄露也拿不到原密码（N=16384,r=8,p=1，单次约 100ms） |
| DPAPI 绑定当前 Windows 用户 | 拷到别的机器/账户解不开 |
| 会话密钥放同一文件 | 改密码 = 换密钥 = 所有设备下线 |
| `timingSafeEqual` | 防时序侧信道 |

## 六、真实坑：第一版我让用户去跑 `node setup.mjs`

第一版没密码时，页面只吐一句话：

> 未设置密码，先运行 `node setup.mjs` 设置访问密码。

用户的原话：

> 这个很难用。没有提示啥也没有。我也是摸索一会才知道咋用的。
> 你要不要设置个页面……如果忘记密码了要怎么操作？

于是重做了三件事：

**1. 设置页**——直接在当前页面输两次密码，插件自己调 `writeState()`（和 `setup.mjs` 同一套逻辑，CLI 变成可选）

**2. 显示密码**——输入框右侧一个「显示」按钮，临时看一眼有没有打错

**3. 忘记密码页**——给出**本机绝对路径** + 三种删法：

```
C:\Users\<你>\.dsh\auth-gate.dat

PowerShell : Remove-Item "C:\Users\<你>\.dsh\auth-gate.dat"
cmd        : del "C:\Users\<你>\.dsh\auth-gate.dat"
资源管理器 : 地址栏 %USERPROFILE%\.dsh → 手动删
```

用户还补了一句："我是在 cmd 下执行的，有些人分不清 cmd 和 PowerShell。"
所以页面上专门标了：**两者语法不同，别混用**。

**教训**：把 CLI 步骤搬进网页，不是"以后再说"的优化，是第一次就该想清楚的事。

## 七、验证：24 项测试 + 真机

`npm test` 用 mock 的 `webServer` 起真实 HTTP 服务：

```
首次初始化 6 项：跳转、设置页、短密码、两次不一致、外网禁止初始化、成功自动登录
登录后      3 项：进首页、Host 重写、DSH cookie 注入
未登录      2 项：HTML 302、API 401
页面与帮助  6 项：登录页、显示密码按钮、忘记密码入口、PowerShell/cmd/绝对路径
密码校验    3 项：错误密码、正确密码、伪造 cookie
其它        2 项：健康检查、限流 429
```

另外起了一个**独立 profile 的真实 DSH 实例**（3090 端口）做端到端：

```
访问 / → 302 /__auth/setup
设置页 → 200
页面提交密码 → 302 + cookie（自动登录）
带 cookie 访问 → 200，<title>DeepSeek Harness</title>
auth-gate.dat → 插件自己写出来的
```

## 八、总结

```
给 DSH 加登录门要理解的事：
├─ DSH 只有 launch token，没有"人"这一层
├─ HTTP 服务没有中间件，只能包 handler
├─ 包完要代签 DSH 的 cookie（浏览器不碰内部凭据）
├─ 密码存 scrypt + DPAPI，不存明文
└─ 首次配置和忘记密码，必须在网页里闭环
```

**一句话**：能用「包一层」解决的，就别去改源码——升级会替你打回原形。

## 技术边界

**已确认**：路由表包装 / cookie 代签 / DPAPI 存储 / 24 项测试 / 真机端到端。

**待深入**：

- 跨平台存储（macOS Keychain / Linux Secret Service）
- 多用户与角色（现在只有一个密码）
- 登录审计（谁在什么时候从哪个 IP 登录）

## 交流群

QQ 群：**1011056058**（DSH 养成计划 · 小白交流群）

一起把 DeepSeek Harness 用起来：装环境、配本地模型、搭自己的工作台。
后面会一起做机器人控制、个人信息整理、成长记录。
不卖课，只聊能跑起来的东西。

* * *

_作者：杜文龙 · 2026-10-25_
_标签：[deepseek-harness][plugin][security][nodejs]_
