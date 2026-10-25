// cordis 插件：接管 webServer 的所有路由，先过门禁再交给 Harness
import { createGate } from './gate.js';

export const name = 'dsh-login-gate';
export const inject = ['webServer'];

const MARK = Symbol.for('dsh-auth-gate.wrapped');

export function apply(ctx, config = {}) {
  const ws = ctx.webServer;
  if (!ws || typeof ws.getOrigin !== 'function') {
    ctx.logger?.warn?.('dsh-auth-gate: 找不到 webServer 服务，跳过');
    return;
  }

  const gate = createGate({
    config,
    logger: ctx.logger ?? console,
    getAuthority: () => ws.getOrigin(),
  });

  const wrapHttp = (fn) => {
    if (typeof fn !== 'function') return fn;
    if (fn[MARK]) return fn;
    const wrapped = gate.wrapHttp(fn);
    Object.defineProperty(wrapped, MARK, { value: true });
    wrapped.__orig = fn;
    return wrapped;
  };
  const wrapUpgrade = (fn) => {
    if (typeof fn !== 'function') return fn;
    if (fn[MARK]) return fn;
    const wrapped = gate.wrapUpgrade(fn);
    Object.defineProperty(wrapped, MARK, { value: true });
    wrapped.__orig = fn;
    return wrapped;
  };

  // 1) 已注册的路由：就地包一层（幂等）
  for (const [k, r] of ws.exact) ws.exact.set(k, { ...r, handler: wrapHttp(r.handler) });
  for (const [k, r] of ws.prefixes) ws.prefixes.set(k, { ...r, handler: wrapHttp(r.handler) });
  for (const [k, r] of ws.upgrades) ws.upgrades.set(k, { ...r, handler: wrapUpgrade(r.handler) });
  if (typeof ws.fallback === 'function') ws.fallback = wrapHttp(ws.fallback);

  // 2) 之后注册的路由：包住 register 系列（只包一次）
  if (!ws[Symbol.for('dsh-auth-gate.patched')]) {
    const origRegister = ws.register.bind(ws);
    const origUpgrade = ws.registerUpgrade.bind(ws);
    const origFallback = ws.registerFallback.bind(ws);

    ws.register = (route) => origRegister({ ...route, handler: wrapHttp(route.handler) });
    ws.registerUpgrade = (route) => origUpgrade({ ...route, handler: wrapUpgrade(route.handler) });
    ws.registerFallback = (handler) => origFallback(wrapHttp(handler));

    Object.defineProperty(ws, Symbol.for('dsh-auth-gate.patched'), { value: true });
  }

  ctx.logger?.info?.('dsh-auth-gate: webServer 已接管，所有请求需要登录');

  // 3) 卸载时尽量还原（进程内热重载用）
  const dispose = () => {
    for (const [k, r] of ws.exact) if (r.handler?.[MARK]) ws.exact.set(k, { ...r, handler: unwrap(r.handler) });
    for (const [k, r] of ws.prefixes) if (r.handler?.[MARK]) ws.prefixes.set(k, { ...r, handler: unwrap(r.handler) });
    for (const [k, r] of ws.upgrades) if (r.handler?.[MARK]) ws.upgrades.set(k, { ...r, handler: unwrap(r.handler) });
    if (typeof ws.fallback === 'function' && ws.fallback[MARK]) ws.fallback = unwrap(ws.fallback);
  };
  try {
    ctx.effect?.(() => dispose);
  } catch {
    /* 没有 effect 能力时忽略 */
  }
}

// 包装函数上挂原函数，便于卸载
function unwrap(fn) {
  return fn.__orig ?? fn;
}
