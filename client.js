// 客户端：设置 → 访问门禁（会话状态 / 改密码 / 有效期）
window.__ModuleLoader__.load({
  id: 'dsh-login-gate',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const S = {
      wrap: { display: 'flex', flexDirection: 'column', gap: 18, maxWidth: 560, fontSize: 13 },
      card: { border: '1px solid rgba(127,127,127,0.28)', borderRadius: 10, padding: '14px 16px' },
      row: { display: 'flex', alignItems: 'center', gap: 8 },
      label: { fontSize: 12, opacity: 0.65, marginBottom: 6, display: 'block' },
      input: {
        width: '100%', padding: '8px 10px', fontSize: 13, color: 'inherit',
        background: 'transparent', border: '1px solid rgba(127,127,127,0.35)',
        borderRadius: 8, fontFamily: 'inherit', boxSizing: 'border-box',
      },
      btn: {
        padding: '7px 14px', fontSize: 13, borderRadius: 8, cursor: 'pointer',
        border: '1px solid rgba(127,127,127,0.35)', background: 'transparent', color: 'inherit',
      },
      primary: { background: '#5eead4', color: '#04110f', border: '0', fontWeight: 600 },
      hint: { fontSize: 12, opacity: 0.6, lineHeight: 1.7 },
      warn: { fontSize: 12, color: '#f0a020' },
      err: { fontSize: 12, color: '#ff6b6b' },
      ok: { fontSize: 12, color: '#3fb950' },
    };

    function Field(props) {
      return h('div', { style: { marginTop: 10 } },
        h('label', { style: S.label }, props.label),
        h('div', { style: { position: 'relative' } },
          h('input', {
            type: props.type, value: props.value, placeholder: props.placeholder,
            autoComplete: props.autoComplete || 'off',
            onChange: (e) => props.onChange(e.target.value),
            style: { ...S.input, paddingRight: props.eye ? 58 : 10 },
          }),
          props.eye
            ? h('button', {
                type: 'button', onClick: props.onEye,
                style: {
                  position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)',
                  fontSize: 11, padding: '4px 8px', background: 'transparent',
                  border: '1px solid rgba(127,127,127,0.35)', borderRadius: 6,
                  color: 'inherit', cursor: 'pointer', opacity: 0.8,
                },
              }, props.eyeText)
            : null,
        ),
      );
    }

    function GatePanel() {
      const [info, setInfo] = React.useState(null);
      const [err, setErr] = React.useState('');
      const [ok, setOk] = React.useState('');
      const [show, setShow] = React.useState(false);
      const [cur, setCur] = React.useState('');
      const [next, setNext] = React.useState('');
      const [cfm, setCfm] = React.useState('');
      const [days, setDays] = React.useState(7);
      const [busy, setBusy] = React.useState(false);

      const load = React.useCallback(() => {
        fetch('/__auth/session-info', { credentials: 'same-origin' })
          .then((r) => r.json().then((j) => {
            if (r.ok) { setInfo(j); setDays(j.sessionDays); }
            else setInfo({ ok: false });
          }))
          .catch(() => setInfo({ ok: false }));
      }, []);

      React.useEffect(() => { load(); }, [load]);

      const submitPassword = () => {
        setErr(''); setOk(''); setBusy(true);
        fetch('/__auth/password', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ current: cur, next, confirm: cfm }).toString(),
        })
          .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
          .then(({ ok, j }) => {
            if (!ok) {
              setErr(j.error === 'current' ? '当前密码不对' : j.error === 'short' ? '新密码至少 6 位' : j.error === 'mismatch' ? '两次输入不一致' : '保存失败');
            } else {
              setOk('密码已更新，其他设备需要重新登录');
              setCur(''); setNext(''); setCfm(''); load();
            }
          })
          .catch(() => setErr('请求失败'))
          .finally(() => setBusy(false));
      };

      const submitDays = () => {
        setErr(''); setOk(''); setBusy(true);
        fetch('/__auth/session-days', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ days: String(days) }).toString(),
        })
          .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
          .then(({ ok, j }) => {
            if (!ok) setErr('有效期需在 1–30 天之间');
            else { setOk('已保存，新登录按这个时长计算'); load(); }
          })
          .catch(() => setErr('请求失败'))
          .finally(() => setBusy(false));
      };

      if (!info) return h('div', { style: S.hint }, '读取状态…');
      if (!info.ok) {
        return h('div', { style: S.card }, h('div', { style: S.hint }, '当前会话已失效，请刷新页面重新登录。'));
      }

      const remaining = typeof info.remainingDays === 'number' ? info.remainingDays : 0;
      const expiring = remaining <= 2;

      return h('div', { style: S.wrap },
        h('div', { style: S.card },
          h('div', { style: { ...S.row, justifyContent: 'space-between' } },
            h('div', null,
              h('div', { style: { fontWeight: 600 } }, '当前会话'),
              h('div', { style: S.hint }, `有效期 ${info.sessionDays} 天，剩余 ${remaining} 天`),
            ),
            h('span', { style: expiring ? { ...S.warn, fontWeight: 600 } : { ...S.hint } },
              expiring ? `⚠ 还有 ${remaining} 天到期` : '正常'),
          ),
          expiring
            ? h('div', { style: { ...S.warn, marginTop: 8 } },
                '快到期了。可以在下面把有效期调长，然后重新登录一次；也可以现在先改个密码，顺便延长。')
            : null,
        ),

        h('div', { style: S.card },
          h('div', { style: { fontWeight: 600, marginBottom: 2 } }, '修改密码'),
          h('div', { style: S.hint }, '改完其他设备会被强制下线。'),
          h(Field, { label: '当前密码', type: show ? 'text' : 'password', value: cur, onChange: setCur, autoComplete: 'current-password' }),
          h(Field, {
            label: '新密码（至少 6 位）', type: show ? 'text' : 'password', value: next, onChange: setNext,
            autoComplete: 'new-password', eye: true, eyeText: show ? '隐藏' : '显示', onEye: () => setShow(!show),
          }),
          h(Field, { label: '再输一次', type: show ? 'text' : 'password', value: cfm, onChange: setCfm, autoComplete: 'new-password' }),
          h('div', { style: { marginTop: 12, display: 'flex', gap: 10, alignItems: 'center' } },
            h('button', { style: { ...S.btn, ...S.primary }, disabled: busy, onClick: submitPassword }, busy ? '保存中…' : '保存密码'),
            err ? h('span', { style: S.err }, err) : null,
            ok ? h('span', { style: S.ok }, ok) : null,
          ),
        ),

        h('div', { style: S.card },
          h('div', { style: { fontWeight: 600, marginBottom: 2 } }, '会话有效期'),
          h('div', { style: S.hint }, '登录后多少天内免输密码（1–30 天）。对之后的新登录生效。'),
          h('div', { style: { marginTop: 10, display: 'flex', gap: 10, alignItems: 'center' } },
            h('input', {
              type: 'number', min: 1, max: 30, value: days,
              onChange: (e) => setDays(Number(e.target.value)),
              style: { ...S.input, width: 90 },
            }),
            h('span', { style: S.hint }, '天'),
            h('button', { style: S.btn, disabled: busy, onClick: submitDays }, '保存'),
          ),
        ),

        h('div', { style: { display: 'flex', gap: 14, fontSize: 12, opacity: 0.7 } },
          h('a', { href: '/__auth/logout', style: { color: 'inherit' } }, '退出登录'),
          h('span', null, '·'),
          h('a', { href: '/__auth/forgot', target: '_blank', rel: 'noreferrer', style: { color: 'inherit' } }, '忘记密码怎么办'),
        ),
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'login-gate',
          order: 60,
          label: () => '访问门禁',
        }, GatePanel));
      },
    };
  },
});
