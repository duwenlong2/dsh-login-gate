// Windows DPAPI 封装：加解密都在本机、绑定当前用户
import { execFileSync } from 'node:child_process';

const PS_ARGS = ['-NoProfile', '-NonInteractive', '-Command'];

function run(script) {
  return execFileSync('powershell', [...PS_ARGS, script], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 20000,
  }).trim();
}

export function protect(bytes) {
  const b64 = Buffer.from(bytes).toString('base64');
  const script = [
    'Add-Type -AssemblyName System.Security',
    `$b=[Convert]::FromBase64String('${b64}')`,
    '$p=[System.Security.Cryptography.ProtectedData]::Protect($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Convert]::ToBase64String($p)',
  ].join('; ');
  return Buffer.from(run(script), 'base64');
}

export function unprotect(buf) {
  const b64 = Buffer.from(buf).toString('base64');
  const script = [
    'Add-Type -AssemblyName System.Security',
    `$b=[Convert]::FromBase64String('${b64}')`,
    '$p=[System.Security.Cryptography.ProtectedData]::Unprotect($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Convert]::ToBase64String($p)',
  ].join('; ');
  return Buffer.from(run(script), 'base64');
}
