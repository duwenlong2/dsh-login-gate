// 门禁核心：会话、密码校验、登录页、请求包装
import { createHmac, createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { protect, unprotect } from './dpapi.js';

const COOKIE = 'dsh_gate';
const AUTH_PREFIX = '/__auth/';
const B64U = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh');
}
export function statePath() {
  return join(dshHome(), 'auth-gate.dat');
}

/** 读并解开 DPAPI 保护的状态文件 */
export function loadState() {
  const p = statePath();
  if (!existsSync(p)) return null;
  try {
    const raw = unprotect(readFileSync(p));
    const s = JSON.parse(raw.toString('utf8'));
    if (s.v !== 1 || !s.hash || !s.salt || !s.secret) return null;
    return {
      hash: Buffer.from(s.hash, 'base64'),
      salt: Buffer.from(s.salt, 'base64'),
      secret: Buffer.from(s.secret, 'base64'),
      sessionDays: typeof s.sessionDays === 'number' ? s.sessionDays : undefined,
      createdAt: s.createdAt,
    };
  } catch {
    return null;
  }
}

/** 把内存里的状态重新加密落盘 */
export function saveState(state) {
  const blob = Buffer.from(JSON.stringify({
    v: 1,
    hash: state.hash.toString('base64'),
    salt: state.salt.toString('base64'),
    secret: state.secret.toString('base64'),
    sessionDays: state.sessionDays,
    createdAt: state.createdAt,
  }), 'utf8');
  const file = statePath();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, protect(blob), { mode: 0o600 });
  return file;
}

/** 写入新密码：scrypt 派生 + DPAPI 加密落盘 */
export function writeState(password, sessionDays) {
  const salt = randomBytes(16);
  return saveState({
    hash: scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }),
    salt,
    secret: randomBytes(32),
    sessionDays,
    createdAt: new Date().toISOString(),
  });
}

/** 读取 DSH 自己的 browser-session secret，用来代签它认的 cookie */
export function loadDshSecret() {
  const file = join(dshHome(), '.credentials.yaml');
  const raw = readFileSync(file, 'utf8');
  const m = raw.match(/client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/);
  if (!m) throw new Error('auth-gate: .credentials.yaml 里找不到 browser-session secret');
  const b64 = m[1].replace(/-/g, '+').replace(/_/g, '/');
  const buf = Buffer.from(b64 + '='.repeat((4 - (m[1].length % 4)) % 4), 'base64');
  if (buf.length !== 32) throw new Error('auth-gate: secret 长度异常');
  return buf;
}

const PAGE = (title, body, extra = '') => `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(1000px 700px at 30% 0%,#12222b,#05070a 60%);
font:14px/1.6 "Microsoft YaHei",system-ui,sans-serif;color:#e6edf3;padding:24px}
.card{width:100%;max-width:420px;background:#0d1117;border:1px solid #222c38;border-radius:16px;
padding:36px 32px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
.badge{display:inline-flex;align-items:center;gap:8px;font:600 11px/1 Consolas,monospace;
letter-spacing:2px;color:#5eead4;margin-bottom:22px}
.dot{width:7px;height:7px;border-radius:50%;background:#5eead4}
h1{font-size:22px;font-weight:700;margin-bottom:8px}
p.sub{color:#7d8fa3;font-size:13px;margin-bottom:26px}
label{display:block;font-size:12px;color:#7d8fa3;margin-bottom:8px;letter-spacing:.5px}
input{width:100%;background:#05070a;border:1px solid #263241;border-radius:10px;padding:13px 14px;
color:#e6edf3;font-size:15px;font-family:inherit;outline:none}
input:focus{border-color:#5eead4}
button{width:100%;margin-top:18px;padding:13px;border:0;border-radius:10px;cursor:pointer;
background:#5eead4;color:#04110f;font-weight:700;font-size:15px;font-family:inherit}
button:disabled{opacity:.5;cursor:not-allowed}
.err{margin-top:16px;padding:11px 13px;border-radius:9px;background:#2a1214;border:1px solid #5b2327;
color:#ff8d86;font-size:13px}
.foot{margin-top:26px;padding-top:18px;border-top:1px solid #1a2330;color:#4f6070;font-size:11.5px;
display:flex;justify-content:space-between}
.hint{margin-top:14px;font-size:12px;color:#5c6b7a}
.hint a{color:#5eead4;text-decoration:none}
.note{margin-top:20px;font-size:11.5px;line-height:1.9;color:#5c6b7a;background:#0a0f15;
border:1px solid #1a2330;border-radius:10px;padding:12px 14px}
.note code{font-family:Consolas,monospace;color:#8b98a8;word-break:break-all}
.steps p{margin:10px 0;color:#a8b6c4;font-size:13px}
.steps pre{margin:8px 0 14px;background:#0a0f15;border:1px solid #1a2330;border-radius:8px;
padding:10px 12px;font-family:Consolas,monospace;font-size:12px;color:#9fb0c0;overflow-x:auto}
.pw{position:relative}
.pw input{padding-right:74px}
.pw .eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:auto;margin:0;
padding:6px 10px;background:#16202b;color:#8b98a8;border:1px solid #263241;border-radius:8px;
font-size:12px;font-weight:400;cursor:pointer;line-height:1}
.pw .eye:hover{color:#e6edf3;border-color:#3a4a5c}
</style></head><body><div class="card">${body}</div>
<script>
document.querySelectorAll('.pw').forEach(function (w) {
  var input = w.querySelector('input');
  var btn = w.querySelector('button');
  if (!input || !btn) return;
  btn.addEventListener('click', function () {
    var show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.textContent = show ? '隐藏' : '显示';
    input.focus();
  });
});
</script></body></html>`;

export function createGate({ config = {}, logger = console, getAuthority }) {
  const title = config.title || 'DSH · 安全入口';
  const sessionDays = config.sessionDays ?? 7;
  const maxFails = config.maxFails ?? 5;
  const lockMinutes = config.lockMinutes ?? 10;
  const allowLocal = config.allowLocal === true;

  let state = null;
  let stateAt = 0;
  let authorityCache = null;
  let dshSecret = null;

  function getState() {
    if (state && Date.now() - stateAt < 30000) return state;
    state = loadState();
    stateAt = Date.now();
    return state;
  }

  function authority() {
    if (authorityCache) return authorityCache;
    try {
      const u = new URL(getAuthority());
      authorityCache = u.host;
    } catch {
      authorityCache = '127.0.0.1:3080';
    }
    return authorityCache;
  }

  function dshCookie() {
    if (!dshSecret) dshSecret = loadDshSecret();
    const now = Date.now();
    const payload = { version: 1, authority: authority(), issuedAt: now, expiresAt: now + 30 * 86400000 };
    const body = B64U(JSON.stringify(payload));
    const sig = B64U(createHmac('sha256', dshSecret).update(body).digest());
    const name = 'dsh-auth-' + B64U(createHash('sha256').update(authority()).digest());
    return `${name}=v1.${body}.${sig}`;
  }

  function verifyPassword(input) {
    const st = getState();
    if (!st || typeof input !== 'string' || input.length === 0) return false;
    const got = scryptSync(input, st.salt, 64, { N: 16384, r: 8, p: 1 });
    return got.length === st.hash.length && timingSafeEqual(got, st.hash);
  }

  /** 会话有效期：状态文件里的覆盖值优先，否则用配置 */
  function effectiveDays() {
    const st = getState();
    return st && typeof st.sessionDays === 'number' ? st.sessionDays : sessionDays;
  }

  function sessionValue(daysOverride) {
    const st = getState();
    const d = typeof daysOverride === 'number' ? daysOverride : effectiveDays();
    const payload = { v: 1, exp: Date.now() + d * 86400000 };
    const body = B64U(JSON.stringify(payload));
    const sig = B64U(createHmac('sha256', st.secret).update(body).digest());
    return `${body}.${sig}`;
  }

  function readCookie(header) {
    if (!header) return '';
    for (const seg of String(header).split(';')) {
      const i = seg.indexOf('=');
      if (i > 0 && seg.slice(0, i).trim() === COOKIE) return seg.slice(i + 1).trim();
    }
    return '';
  }

  /** 解出会话载荷（验签 + 未过期），失败返回 null */
  function readSession(req) {
    const st = getState();
    if (!st) return null;
    const token = readCookie(req.headers.cookie);
    const i = token.lastIndexOf('.');
    if (i < 1) return null;
    const body = token.slice(0, i);
    const sig = token.slice(i + 1);
    const expect = B64U(createHmac('sha256', st.secret).update(body).digest());
    const a = Buffer.from(sig);
    const b = Buffer.from(expect);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    try {
      const p = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
      return typeof p.exp === 'number' && p.exp > Date.now() ? p : null;
    } catch {
      return null;
    }
  }

  function isAuthenticated(req) {
    return readSession(req) !== null;
  }

  const fails = new Map();
  function ipOf(req) {
    return String(req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
  }
  function lockedFor(ip) {
    const r = fails.get(ip);
    if (!r) return 0;
    if (Date.now() > r.until) { fails.delete(ip); return 0; }
    return r.count >= maxFails ? r.until - Date.now() : 0;
  }
  function noteFail(ip) {
    const r = fails.get(ip) || { count: 0, until: 0 };
    r.count += 1;
    r.until = Date.now() + lockMinutes * 60000;
    fails.set(ip, r);
  }

  function isLoopback(req) {
    const a = String(req.socket?.remoteAddress || '');
    const loop = a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
    return loop && !req.headers['cf-connecting-ip'] && !req.headers['x-forwarded-for'];
  }

  function loginBody(error, locked, disabled = false) {
    return `<div class="badge"><span class="dot"></span>DSH · SECURE GATE</div>
<h1>需要登录</h1><p class="sub">${title}</p>
<form method="POST" action="/__auth/login">
<label for="p">访问密码</label>
<div class="pw"><input id="p" name="password" type="password" autocomplete="current-password" autofocus required ${disabled ? 'disabled' : ''}><button type="button" class="eye" tabindex="-1">显示</button></div>
<button type="submit" ${disabled ? 'disabled' : ''}>进入</button></form>
${error ? `<div class="err">${error}</div>` : ''}
<div class="hint">忘记密码？<a href="/__auth/forgot">看这里</a></div>
<div class="foot"><span>DeepSeek Harness</span><span>${locked ? '已锁定' : 'session ' + sessionDays + 'd'}</span></div>`;
  }

  function setupBody(error = '') {
    return `<div class="badge"><span class="dot"></span>DSH · SECURE GATE</div>
<h1>设置访问密码</h1>
<p class="sub">第一次使用，先给这个入口设一个密码。以后每次打开都要输入。</p>
<form method="POST" action="/__auth/setup">
<label for="p1">密码（至少 6 位）</label>
<div class="pw"><input id="p1" name="password" type="password" autocomplete="new-password" autofocus required minlength="6"><button type="button" class="eye" tabindex="-1">显示</button></div>
<label for="p2" style="margin-top:14px">再输一次</label>
<div class="pw"><input id="p2" name="confirm" type="password" autocomplete="new-password" required minlength="6"><button type="button" class="eye" tabindex="-1">显示</button></div>
<button type="submit">保存并进入</button></form>
${error ? `<div class="err">${error}</div>` : ''}
<div class="note">密码只存 scrypt 派生值，用 Windows DPAPI 加密后写在：<br><code>${statePath()}</code><br>换一台机器或换一个 Windows 用户都解不开。</div>
<div class="foot"><span>DeepSeek Harness</span><span>首次初始化</span></div>`;
  }

  function forgotBody() {
    const file = statePath();
    return `<div class="badge"><span class="dot"></span>DSH · SECURE GATE</div>
<h1>忘记密码</h1>
<p class="sub">密码无法找回，但可以重置。重置需要能操作这台电脑。</p>

<div class="steps">
<p><b>1.</b> 要删的文件就在这台机器上：</p>
<pre>${file}</pre>

<p><b>2.</b> 下面三种方式任选一种删掉它（注意 cmd 和 PowerShell 语法不同，别混用）：</p>

<p>PowerShell：</p>
<pre>Remove-Item "${file}"</pre>

<p>命令提示符（cmd）：</p>
<pre>del "${file}"</pre>

<p>文件资源管理器（最稳妥，不怕命令写错）：</p>
<pre>地址栏粘贴：%USERPROFILE%\\.dsh
然后手动删除 auth-gate.dat</pre>

<p><b>3.</b> 回到浏览器刷新本页，会重新出现「设置访问密码」，设一个新密码即可。</p>
</div>

<div class="note">为什么要这么麻烦：密码不存数据库，只存 scrypt 派生值，所以没有“找回”只有“重置”。<br>删掉这个文件 = 清空所有已登录设备，相当于强制下线。</div>
<div class="hint"><a href="/__auth/login">← 返回登录</a></div>
<div class="foot"><span>DeepSeek Harness</span><span>reset</span></div>`;
  }

  function initBlockedBody() {
    return `<h1>还没有设置密码</h1>
<p class="sub">这台机器的 DSH 门禁尚未初始化。</p>
<div class="note">为安全起见，初始化只允许在<b>本机</b>完成。<br>请在这台电脑上打开：<br><code>http://127.0.0.1:${authority().split(':')[1] || '3080'}</code></div>`;
  }

  function send(res, status, html, extraHeaders = {}) {
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      ...extraHeaders,
    });
    res.end(html);
  }

  /** 处理 /__auth/*，返回 true 表示已接管 */
  async function handleAuth(req, res, pathname) {
    if (pathname === '/__auth/health') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ ok: true, protected: true, hasPassword: !!getState() }));
      return true;
    }

    const json = (code, obj, extra = {}) => {
      res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra });
      res.end(JSON.stringify(obj));
      return true;
    };

    if (pathname === '/__auth/session-info') {
      const s = readSession(req);
      if (!s) return json(401, { ok: false, error: 'unauthorized' });
      const days = effectiveDays();
      const ms = s.exp - Date.now();
      return json(200, {
        ok: true,
        expiresAt: s.exp,
        sessionDays: days,
        remainingDays: Math.max(0, Math.round((ms / 86400000) * 10) / 10),
        hasPassword: !!getState(),
        allowLocal,
      });
    }

    if (pathname === '/__auth/password' && req.method === 'POST') {
      if (!readSession(req)) return json(401, { ok: false, error: 'unauthorized' });
      const body = new URLSearchParams(await readBody(req));
      const current = body.get('current') || '';
      const next = body.get('next') || '';
      const confirm = body.get('confirm') || '';
      if (!verifyPassword(current)) return json(401, { ok: false, error: 'current' });
      if (next.length < 6) return json(400, { ok: false, error: 'short' });
      if (next !== confirm) return json(400, { ok: false, error: 'mismatch' });
      const days = effectiveDays();
      writeState(next, days);
      state = null;
      stateAt = 0;
      const secure = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
      const cookie = `${COOKIE}=${sessionValue()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${days * 86400}${secure ? '; Secure' : ''}`;
      return json(200, { ok: true, sessionDays: days }, { 'set-cookie': cookie });
    }

    if (pathname === '/__auth/session-days' && req.method === 'POST') {
      if (!readSession(req)) return json(401, { ok: false, error: 'unauthorized' });
      const body = new URLSearchParams(await readBody(req));
      const days = Number(body.get('days'));
      if (!Number.isInteger(days) || days < 1 || days > 30) return json(400, { ok: false, error: 'range' });
      const st = getState();
      st.sessionDays = days;
      saveState(st);
      state = st;
      stateAt = Date.now();
      // 立即续期：当前会话也按新时长重签，界面上的剩余天数会马上刷新
      const secure = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
      const cookie = `${COOKIE}=${sessionValue(days)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${days * 86400}${secure ? '; Secure' : ''}`;
      return json(200, { ok: true, sessionDays: days, expiresAt: Date.now() + days * 86400000 }, { 'set-cookie': cookie });
    }
    if (pathname === '/__auth/setup') {
      if (getState()) {
        res.writeHead(302, { location: '/__auth/login', 'cache-control': 'no-store' });
        res.end();
        return true;
      }
      if (!isLoopback(req)) {
        send(res, 403, PAGE(title, `<h1>只能在本机初始化</h1>
<p class="sub">为安全起见，第一次设置密码只能在这台电脑上完成。</p>
<div class="note">请在本机浏览器打开 <code>http://127.0.0.1:${authority()}</code> 完成设置。</div>`));
        return true;
      }
      if (req.method === 'GET') {
        send(res, 200, PAGE(title, setupBody()));
        return true;
      }
      if (req.method === 'POST') {
        const body = new URLSearchParams(await readBody(req));
        const pw = body.get('password') || '';
        const cf = body.get('confirm') || '';
        if (pw.length < 6) { send(res, 400, PAGE(title, setupBody('密码至少 6 位。'))); return true; }
        if (pw !== cf) { send(res, 400, PAGE(title, setupBody('两次输入不一致。'))); return true; }
        try {
          writeState(pw, sessionDays);
          state = null;
          stateAt = 0;
        } catch (e) {
          send(res, 500, PAGE(title, setupBody('写入失败：' + String(e.message || e).replace(/[<>&]/g, ''))));
          return true;
        }
        const secure = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
        const cookie = `${COOKIE}=${sessionValue()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${effectiveDays() * 86400}${secure ? '; Secure' : ''}`;
        res.writeHead(302, { location: '/', 'set-cookie': cookie, 'cache-control': 'no-store' });
        res.end();
        return true;
      }
    }

    if (pathname === '/__auth/forgot' && req.method === 'GET') {
      send(res, 200, PAGE(title, forgotBody()));
      return true;
    }

    if (pathname === '/__auth/logout') {
      res.writeHead(302, { location: '/__auth/login', 'set-cookie': `${COOKIE}=; Path=/; Max-Age=0`, 'cache-control': 'no-store' });
      res.end();
      return true;
    }
    if (pathname === '/__auth/login' && req.method === 'GET') {
      send(res, 200, PAGE(title, loginBody('', lockedFor(ipOf(req)) > 0)));
      return true;
    }
    if (pathname === '/__auth/login' && req.method === 'POST') {
      const ip = ipOf(req);
      const lock = lockedFor(ip);
      if (lock > 0) { send(res, 429, PAGE(title, loginBody('尝试次数过多，请稍后再试。', true, true))); return true; }
      const body = await readBody(req);
      const pw = new URLSearchParams(body).get('password') || '';
      if (!verifyPassword(pw)) {
        noteFail(ip);
        send(res, 401, PAGE(title, loginBody('密码不正确。', lockedFor(ip) > 0)));
        return true;
      }
      fails.delete(ip);
      const secure = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
      const cookie = `${COOKIE}=${sessionValue()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${effectiveDays() * 86400}${secure ? '; Secure' : ''}`;
      const next = new URL(req.url || '/', 'http://x').searchParams.get('next');
      const to = next && next.startsWith('/') && !next.startsWith('//') ? next : '/';
      res.writeHead(302, { location: to, 'set-cookie': cookie, 'cache-control': 'no-store' });
      res.end();
      return true;
    }
    send(res, 404, PAGE(title, '<h1>404</h1>'));
    return true;
  }

  function readBody(req) {
    return new Promise((resolve) => {
      let data = '';
      req.on('data', (c) => { data += c; if (data.length > 4096) req.destroy(); });
      req.on('end', () => resolve(data));
      req.on('error', () => resolve(''));
    });
  }

  /** 给上游补上 DSH 认的 cookie 和 Host/Origin */
  function injectUpstream(req) {
    const a = authority();
    const dsh = dshCookie();
    const merged = req.headers.cookie ? `${req.headers.cookie}; ${dsh}` : dsh;
    req.headers.cookie = merged;
    req.headers.host = a;
    if (req.headers.origin) req.headers.origin = `http://${a}`;
  }

  /** HTTP 处理器包装 */
  function wrapHttp(handler) {
    return async (req, res) => {
      const pathname = (() => {
        try { return new URL(req.url || '/', 'http://x').pathname; } catch { return '/'; }
      })();
      if (pathname.startsWith(AUTH_PREFIX)) return handleAuth(req, res, pathname);
      if (!getState()) {
        if (isLoopback(req)) {
          res.writeHead(302, { location: '/__auth/setup', 'cache-control': 'no-store' });
          res.end();
          return;
        }
        send(res, 503, PAGE(title, initBlockedBody()));
        return;
      }
      if (allowLocal && isLoopback(req)) { injectUpstream(req); return handler(req, res); }
      if (!isAuthenticated(req)) {
        const wantsHtml = req.method === 'GET' && String(req.headers.accept || '').includes('text/html');
        if (wantsHtml) {
          res.writeHead(302, { location: '/__auth/login?next=' + encodeURIComponent(req.url || '/'), 'cache-control': 'no-store' });
          res.end();
          return;
        }
        res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      injectUpstream(req);
      return handler(req, res);
    };
  }

  /** WebSocket 升级包装 */
  function wrapUpgrade(handler) {
    return (req, socket, head) => {
      const pathname = (() => {
        try { return new URL(req.url || '/', 'http://x').pathname; } catch { return '/'; }
      })();
      if (pathname.startsWith(AUTH_PREFIX)) { socket.destroy(); return; }
      if (!(allowLocal && isLoopback(req)) && !isAuthenticated(req)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        socket.destroy();
        return;
      }
      injectUpstream(req);
      return handler(req, socket, head);
    };
  }

  return { wrapHttp, wrapUpgrade, handleAuth, isAuthenticated, getState, authority, verifyPassword, sessionValue };
}
