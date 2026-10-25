#!/usr/bin/env node
/**
 * dsh-auth-gate/setup.mjs — 设置访问密码
 *
 * 密码用 scrypt 派生，派生物 + 会话密钥放进 DPAPI 保护的文件：
 *   %DSH_HOME%\auth-gate.dat   (默认 ~/.dsh/auth-gate.dat)
 *
 * 用法:
 *   node setup.mjs                      交互式
 *   DSH_GATE_PASSWORD=xxx node setup.mjs 非交互
 */
import { randomBytes, scryptSync } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createInterface } from 'node:readline';
import { protect } from './dpapi.js';
import { statePath } from './gate.js';

function askHidden(question) {
  return new Promise((resolve) => {
    process.stdout.write(question);
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const orig = rl._writeToOutput?.bind(rl);
    if (orig) rl._writeToOutput = (s) => { if (s.includes('\n')) orig(s); };
    rl.question('', (answer) => { rl.close(); process.stdout.write('\n'); resolve(answer); });
  });
}

let password = process.env.DSH_GATE_PASSWORD;
if (!password) {
  password = await askHidden('设置访问密码: ');
  const again = await askHidden('再输一次: ');
  if (password !== again) {
    console.error('两次输入不一致');
    process.exit(1);
  }
}
if (!password || password.length < 6) {
  console.error('密码至少 6 位');
  process.exit(1);
}

const salt = randomBytes(16);
const hash = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
const secret = randomBytes(32);

const blob = Buffer.from(JSON.stringify({
  v: 1,
  hash: hash.toString('base64'),
  salt: salt.toString('base64'),
  secret: secret.toString('base64'),
  createdAt: new Date().toISOString(),
}), 'utf8');

const encrypted = protect(blob);
const file = statePath();
mkdirSync(dirname(file), { recursive: true });
writeFileSync(file, encrypted, { mode: 0o600 });

console.log('已写入 ' + file);
console.log('（DPAPI 加密，绑定当前 Windows 用户；复制到别的机器无法解开）');
