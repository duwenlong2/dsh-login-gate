// 预览用：在 3095 起一个只有门禁的假服务器，方便截图三个页面
import http from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const home = process.env.PREVIEW_HOME || mkdtempSync(join(tmpdir(), 'dsh-gate-preview-'));
process.env.DSH_HOME = home;
mkdirSync(home, { recursive: true });
// 已有真实凭据时不要覆盖（用真实 home 截图时）
if (!existsSync(join(home, '.credentials.yaml'))) {
  const secret = randomBytes(32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  writeFileSync(join(home, '.credentials.yaml'), [
    'version: 1', 'records:', '  client-connection/browser-session:', '    kind: grant',
    '    payload:', '      version: 1', `      secret: ${secret}`, '',
  ].join('\n'), 'utf8');
}

const { apply } = await import('../index.js');
const PORT = 3095;
const ws = {
  exact: new Map(), prefixes: new Map(), upgrades: new Map(), fallback: undefined,
  getOrigin: () => `http://127.0.0.1:${PORT}`,
  register(r) { (r.kind === 'exact' ? this.exact : this.prefixes).set(r.path, r); return () => {}; },
  registerUpgrade(r) { this.upgrades.set(r.path, r); return () => {}; },
  registerFallback(h) { this.fallback = h; return () => {}; },
};
ws.register({ kind: 'exact', path: '/', handler: (q, s) => { s.writeHead(200); s.end('harness'); } });
ws.registerFallback((q, s) => { s.writeHead(200, { 'content-type': 'text/html' }); s.end('<title>Harness</title><h1>harness</h1>'); });
apply({ webServer: ws, logger: { info() {}, warn() {} }, effect: () => {} }, { sessionDays: 7, allowLocal: false });

http.createServer(async (req, res) => {
  const p = new URL(req.url || '/', 'http://x').pathname;
  let route = ws.exact.get(p);
  if (!route) for (const [k, r] of ws.prefixes) if (p.startsWith(k)) route = r;
  if (route) return route.handler(req, res);
  if (ws.fallback) return ws.fallback(req, res);
  res.writeHead(404); res.end();
}).listen(PORT, '127.0.0.1', () => console.log('preview on', PORT, 'home', home));
