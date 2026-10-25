// 隔离测试：mock webServer + 真实 HTTP，覆盖「首次设置 → 登录 → 忘记密码」全流程
import http from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

// 独立 DSH_HOME，避免动到真实凭据
const home = mkdtempSync(join(tmpdir(), 'dsh-gate-test-'));
process.env.DSH_HOME = home;
mkdirSync(home, { recursive: true });
const secret = randomBytes(32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
writeFileSync(join(home, '.credentials.yaml'), [
  'version: 1',
  'records:',
  '  client-connection/browser-session:',
  '    kind: grant',
  '    payload:',
  '      version: 1',
  `      secret: ${secret}`,
  '',
].join('\n'), 'utf8');

const { apply } = await import('../index.js');

const PORT = 3099;
const ws = {
  exact: new Map(),
  prefixes: new Map(),
  upgrades: new Map(),
  fallback: undefined,
  getOrigin: () => `http://127.0.0.1:${PORT}`,
  register(route) {
    const t = route.kind === 'exact' ? this.exact : this.prefixes;
    t.set(route.path, route);
    return () => t.delete(route.path);
  },
  registerUpgrade(route) { this.upgrades.set(route.path, route); return () => this.upgrades.delete(route.path); },
  registerFallback(h) { this.fallback = h; return () => { this.fallback = undefined; }; },
};

ws.register({
  kind: 'exact', path: '/',
  handler: (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ viewer: 'index', host: req.headers.host, cookie: req.headers.cookie || '' }));
  },
});
ws.register({
  kind: 'prefix', path: '/api/',
  handler: (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ viewer: 'api', host: req.headers.host }));
  },
});
ws.registerFallback((req, res) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end('<title>SPA</title>');
});

apply({ webServer: ws, logger: { info() {}, warn() {} }, effect: () => {} }, { sessionDays: 7, allowLocal: false });

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url || '/', 'http://x').pathname;
  let route = ws.exact.get(p);
  if (!route) for (const [k, r] of ws.prefixes) if (p.startsWith(k)) route = r;
  if (route) return route.handler(req, res);
  if (ws.fallback) return ws.fallback(req, res);
  res.writeHead(404); res.end();
});
await new Promise((r) => server.listen(PORT, '127.0.0.1', r));

const base = `http://127.0.0.1:${PORT}`;
const PW = 'MyPass#2026';
let pass = 0, fail = 0;
const check = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${extra}`); }
};
const post = (path, body, headers = {}) => fetch(base + path, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
  body,
  redirect: 'manual',
});

console.log('— 首次初始化 —');
let r = await fetch(base + '/', { headers: { accept: 'text/html' }, redirect: 'manual' });
check('未设置密码时访问 / → 302 到设置页', r.status === 302 && (r.headers.get('location') || '') === '/__auth/setup');

r = await fetch(base + '/__auth/setup');
let html = await r.text();
check('设置页 200，有密码+确认两个输入', r.status === 200 && html.includes('name="password"') && html.includes('name="confirm"'));
check('设置页有两个「显示密码」按钮', (html.match(/class="eye"/g) || []).length === 2);

r = await post('/__auth/setup', 'password=abc&confirm=abc');
check('密码太短 → 400', r.status === 400);

r = await post('/__auth/setup', `password=${encodeURIComponent(PW)}&confirm=different`);
check('两次不一致 → 400', r.status === 400);

r = await post('/__auth/setup', `password=${encodeURIComponent(PW)}&confirm=${encodeURIComponent(PW)}`, { 'cf-connecting-ip': '203.0.113.5' });
check('外网不能初始化 → 403', r.status === 403);

r = await post('/__auth/setup', `password=${encodeURIComponent(PW)}&confirm=${encodeURIComponent(PW)}`);
const setupCookie = (r.headers.get('set-cookie') || '').split(';')[0];
check('本机设置成功 → 302 + 自动登录 cookie', r.status === 302 && setupCookie.startsWith('dsh_gate='));

console.log('— 登录后 —');
r = await fetch(base + '/', { headers: { cookie: setupCookie } });
let body = await r.json();
check('初始化后直接可进首页', r.status === 200 && body.viewer === 'index');
check('Host 被重写', body.host === `127.0.0.1:${PORT}`, body.host);
check('注入了 DSH cookie', body.cookie.includes('dsh-auth-'));

console.log('— 未登录访问 —');
r = await fetch(base + '/', { headers: { accept: 'text/html' }, redirect: 'manual' });
check('HTML → 302 登录页', r.status === 302 && (r.headers.get('location') || '').startsWith('/__auth/login'));
r = await fetch(base + '/api/x', { redirect: 'manual' });
check('API → 401', r.status === 401);

console.log('— 登录页与帮助 —');
r = await fetch(base + '/__auth/login');
html = await r.text();
check('登录页 200', r.status === 200 && html.includes('name="password"'));
check('登录页有「显示密码」按钮', html.includes('class="eye"'));
check('登录页有「忘记密码」入口', html.includes('/__auth/forgot'));
r = await fetch(base + '/__auth/forgot');
html = await r.text();
check('忘记密码页给出 PowerShell 命令', r.status === 200 && html.includes('Remove-Item'));
check('忘记密码页给出 cmd 命令', html.includes('del &quot;') || html.includes('del "'));
check('忘记密码页给出绝对路径', html.includes('auth-gate.dat') && html.includes(home));
check('忘记密码页给出资源管理器方式', html.includes('%USERPROFILE%'));

console.log('— 密码校验 —');
r = await post('/__auth/login', 'password=wrong');
check('错误密码 → 401', r.status === 401);
r = await post('/__auth/login', `password=${encodeURIComponent(PW)}`);
const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
check('正确密码 → 302 + cookie', r.status === 302 && cookie.startsWith('dsh_gate='));
r = await fetch(base + '/', { headers: { cookie: 'dsh_gate=bad.value' }, redirect: 'manual' });
check('伪造 cookie → 拒绝', r.status === 401 || r.status === 302);

console.log('— 设置页接口 —');
r = await fetch(base + '/__auth/session-info', { headers: { cookie } });
let si = await r.json();
check('会话信息：天数 7', r.status === 200 && si.ok === true && si.sessionDays === 7, JSON.stringify(si));
check('会话信息：剩余天数约 7', si.remainingDays > 6.9 && si.remainingDays <= 7);

r = await fetch(base + '/__auth/session-info');
check('未登录读会话信息 → 401', r.status === 401);

r = await post('/__auth/session-days', 'days=14', { cookie });
let sd = await r.json();
check('改有效期 14 天 → ok', r.status === 200 && sd.sessionDays === 14);
r = await fetch(base + '/__auth/session-info', { headers: { cookie } });
si = await r.json();
check('会话信息读到 14 天', si.sessionDays === 14);

r = await post('/__auth/session-days', 'days=99', { cookie });
check('有效期越界 → 400', r.status === 400);

r = await post('/__auth/password', 'current=wrong&next=NewPass%232026&confirm=NewPass%232026', { cookie });
check('改密码：当前密码错 → 401', r.status === 401);

r = await post('/__auth/password', `current=${encodeURIComponent(PW)}&next=abc&confirm=abc`, { cookie });
check('改密码：新密码太短 → 400', r.status === 400);

r = await post('/__auth/password', `current=${encodeURIComponent(PW)}&next=NewPass%232026&confirm=other`, { cookie });
check('改密码：两次不一致 → 400', r.status === 400);

r = await post('/__auth/password', `current=${encodeURIComponent(PW)}&next=NewPass%232026&confirm=NewPass%232026`, { cookie });
const newCookie = (r.headers.get('set-cookie') || '').split(';')[0];
check('改密码成功 → 200 + 新 cookie', r.status === 200 && newCookie.startsWith('dsh_gate='));

r = await fetch(base + '/', { headers: { cookie }, redirect: 'manual' });
check('旧会话已失效', r.status === 401 || r.status === 302);
r = await fetch(base + '/', { headers: { cookie: newCookie } });
check('新会话可用', r.status === 200);

console.log('— 其它 —');
r = await fetch(base + '/__auth/health');
const health = await r.json();
check('健康检查', r.status === 200 && health.hasPassword === true);
let limited = false;
for (let i = 0; i < 7; i++) {
  const rr = await post('/__auth/login', 'password=bad' + i, { 'cf-connecting-ip': '198.51.100.9' });
  if (rr.status === 429) limited = true;
}
check('连续失败触发 429', limited);

console.log(`\n${pass} passed, ${fail} failed  (DSH_HOME=${home})`);
server.close();
process.exit(fail === 0 ? 0 : 1);
