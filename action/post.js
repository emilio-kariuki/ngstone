const { execFileSync } = require('child_process');

function state(name) {
  const value = process.env[`STATE_${name.toUpperCase()}`] || process.env[`STATE_${name}`];
  if (!value) return '';
  try { return Buffer.from(value, 'base64url').toString('utf8'); } catch { return ''; }
}

function stopProcess(pid) {
  if (!/^\d+$/.test(String(pid))) return;
  const numericPID = Number(pid);
  try {
    process.kill(-numericPID, 'SIGTERM');
  } catch {
    try { process.kill(numericPID, 'SIGTERM'); } catch {}
  }
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try { process.kill(numericPID, 0); } catch { return; }
    try { execFileSync('sleep', ['0.1'], { stdio: 'ignore' }); } catch { break; }
  }
  try { process.kill(-numericPID, 'SIGKILL'); } catch { try { process.kill(numericPID, 'SIGKILL'); } catch {} }
}

async function revoke(server, token, credentialID) {
  if (!server || !token || !credentialID) return;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(new URL(`/api/v1/credentials/${encodeURIComponent(credentialID)}`, server), { method: 'DELETE', headers: { Authorization: `Bearer ${token}` }, signal: controller.signal, redirect: 'error' });
    if (!response.ok) throw new Error(`status ${response.status}`);
  } finally {
    clearTimeout(timer);
  }
}

async function post() {
  stopProcess(state('pid'));
  const server = state('credential_server');
  const token = state('credential_token');
  const credentialID = state('credential_id');
  if (!server || !token || !credentialID) return;
  try {
    await revoke(server, token, credentialID);
    process.stdout.write('ngstone workflow credential revoked\n');
  } catch (error) {
    process.stderr.write(`ngstone could not revoke workflow credential: ${error.message}\n`);
    process.exitCode = 1;
  }
}

post().catch((error) => {
  process.stderr.write(`ngstone cleanup failed: ${error.message}\n`);
  process.exitCode = 1;
});
