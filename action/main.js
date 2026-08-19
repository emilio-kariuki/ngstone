const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawn, spawnSync } = require('child_process');

function input(name) {
  const suffix = name.toUpperCase().replace(/ /g, '_');
  return String(process.env[`INPUT_${suffix}`] || process.env[`INPUT_${suffix.replace(/-/g, '_')}`] || '').trim();
}

function requiredInput(name) {
  const value = input(name);
  if (!value) throw new Error(`input ${name} is required`);
  return value;
}

function mask(value) {
  if (value) process.stdout.write(`::add-mask::${value}\n`);
}

function appendFile(file, value) {
  if (!file) throw new Error('GitHub Actions output file is unavailable');
  fs.appendFileSync(file, value, { encoding: 'utf8', mode: 0o600 });
}

function setOutput(name, value) {
  appendFile(process.env.GITHUB_OUTPUT, `${name}=${String(value)}\n`);
}

function setState(name, value) {
  appendFile(process.env.GITHUB_STATE, `${name}=${Buffer.from(String(value)).toString('base64url')}\n`);
}

function validateRepository(repository) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error('repository must be in owner/name form');
}

function validateVersion(version) {
  if (version !== 'latest' && !/^[A-Za-z0-9._-]+$/.test(version)) throw new Error('version contains unsupported characters');
}

function validateURL(raw, name) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${name} must be an http(s) URL`);
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) throw new Error(`${name} must be an http(s) URL without credentials, query, or fragment`);
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '::1'].includes(url.hostname.toLowerCase())) throw new Error(`${name} must use HTTPS unless it points to localhost`);
  return url;
}

async function requestJSON(url, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal, redirect: 'error' });
    const text = await response.text();
    let body = {};
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = {};
      }
    }
    if (!response.ok) throw new Error(`management API request failed with status ${response.status}`);
    return body;
  } finally {
    clearTimeout(timer);
  }
}

async function issueCredential(server, adminToken, subdomain, ttl) {
  const response = await requestJSON(new URL('/api/v1/credentials', server), {
    method: 'POST',
    headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'http', subdomain, ttl }),
  });
  const credential = response.data && response.data.credential;
  const token = response.data && response.data.token;
  if (!credential || !credential.id || !token) throw new Error('management API returned an incomplete credential');
  return { credential, token };
}

function generatedSubdomain() {
  const repo = process.env.GITHUB_REPOSITORY || 'repository';
  const workflow = process.env.GITHUB_WORKFLOW || 'workflow';
  const digest = crypto.createHash('sha256').update(`${repo}:${workflow}`).digest('hex').slice(0, 8);
  const run = (process.env.GITHUB_RUN_ID || 'run').replace(/[^a-z0-9-]/gi, '').toLowerCase();
  const attempt = (process.env.GITHUB_RUN_ATTEMPT || '1').replace(/[^a-z0-9-]/gi, '').toLowerCase();
  return `gha-${run || 'run'}-${attempt || '1'}-${digest}`.slice(0, 63).replace(/-+$/, '');
}

function validateSubdomain(value) {
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) throw new Error('subdomain must be a DNS-safe label');
}

function validatePublicURL(value) {
  if (!value || /[\r\n]/.test(value)) throw new Error('ngstone announced an invalid tunnel URL');
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('ngstone announced an invalid tunnel URL');
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) throw new Error('ngstone announced an invalid tunnel URL');
  return value;
}

function runnerAsset() {
  const platform = process.platform;
  const architecture = process.arch;
  if (platform === 'linux' && architecture === 'x64') return 'linux_amd64';
  if (platform === 'linux' && architecture === 'arm64') return 'linux_arm64';
  if (platform === 'darwin' && architecture === 'x64') return 'darwin_amd64';
  if (platform === 'darwin' && architecture === 'arm64') return 'darwin_arm64';
  throw new Error(`unsupported runner ${platform}/${architecture}`);
}

async function downloadBinary(repository, version) {
  const asset = runnerAsset();
  const base = version === 'latest' ? `https://github.com/${repository}/releases/latest/download` : `https://github.com/${repository}/releases/download/${version}`;
  const directory = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'ngstone-action');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const archiveName = `ngstone_${asset}.tar.gz`;
  const archivePath = path.join(directory, archiveName);
  const checksumsPath = path.join(directory, 'checksums.txt');
  const archiveResponse = await fetch(`${base}/${archiveName}`, { redirect: 'error' });
  if (!archiveResponse.ok) throw new Error(`could not download ngstone release (${archiveResponse.status})`);
  fs.writeFileSync(archivePath, Buffer.from(await archiveResponse.arrayBuffer()), { mode: 0o600 });
  const checksumsResponse = await fetch(`${base}/checksums.txt`, { redirect: 'error' });
  if (!checksumsResponse.ok) throw new Error(`could not download release checksums (${checksumsResponse.status})`);
  fs.writeFileSync(checksumsPath, await checksumsResponse.text(), { mode: 0o600 });
  const checksumLine = fs.readFileSync(checksumsPath, 'utf8').split(/\r?\n/).find((line) => line.trim().split(/\s+/).pop() === archiveName);
  const expected = checksumLine && checksumLine.trim().split(/\s+/)[0];
  if (!expected || !/^[a-f0-9]{64}$/i.test(expected)) throw new Error(`release checksums do not contain ${archiveName}`);
  const actual = crypto.createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');
  if (actual.toLowerCase() !== expected.toLowerCase()) throw new Error(`checksum verification failed for ${archiveName}`);
  execFileSync('tar', ['-xzf', archivePath, '-C', directory], { stdio: 'ignore' });
  const binary = path.join(directory, 'ngstone');
  fs.chmodSync(binary, 0o755);
  return binary;
}

function stopProcess(pid) {
  if (!/^\d+$/.test(String(pid))) return;
  const numericPID = Number(pid);
  try {
    process.kill(-numericPID, 'SIGTERM');
  } catch {
    try { process.kill(numericPID, 'SIGTERM'); } catch {}
  }
}

function readOnlineURL(logPath) {
  if (!fs.existsSync(logPath)) return '';
  const lines = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).reverse();
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      if (event && event.state === 'online' && typeof event.url === 'string' && event.url) return event.url;
    } catch {}
  }
  return '';
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function startTunnel(binary, target, token, server, transport, serverName, subdomain, hostHeader, ttl, waitTimeout, insecure) {
  const command = [binary, 'port', target, '--no-tui', '--json', '--ttl', ttl, '--server', server, '--transport', transport, '--server-name', serverName, '--subdomain', subdomain];
  if (hostHeader) command.push('--host-header', hostHeader);
  if (insecure === 'true') command.push('--insecure');
  const logPath = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'ngstone-action.log');
  const logFile = fs.openSync(logPath, 'a', 0o600);
  const child = spawn(command[0], command.slice(1), { detached: true, env: { ...process.env, NGSTONE_TOKEN: token }, stdio: ['ignore', logFile, logFile] });
  fs.closeSync(logFile);
  if (!child.pid) throw new Error('ngstone process did not start');
  setState('pid', child.pid);
  const deadline = Date.now() + Math.max(1, Number.parseInt(waitTimeout || '60', 10)) * 1000;
  while (Date.now() < deadline) {
    const url = readOnlineURL(logPath);
    if (url) return { pid: child.pid, logPath, url };
    if (child.exitCode !== null) throw new Error('ngstone exited before announcing a tunnel URL');
    await wait(250);
  }
  stopProcess(child.pid);
  throw new Error('timed out waiting for ngstone tunnel URL');
}

async function main() {
  const target = requiredInput('target');
  const server = input('server') || 'ngstone.site:4443';
  const transport = input('transport') || 'auto';
  const serverName = input('server-name') || 'ngstone.site';
  const ttl = input('ttl') || '30m';
  const adminToken = input('admin-token');
  const legacyToken = input('token');
  let token = legacyToken;
  let subdomain = input('subdomain').toLowerCase();
  if (adminToken) {
    const adminServer = validateURL(input('admin-server'), 'admin-server');
    subdomain = subdomain || generatedSubdomain();
    validateSubdomain(subdomain);
    mask(adminToken);
    const issued = await issueCredential(adminServer, adminToken, subdomain, ttl);
    token = issued.token;
    mask(token);
    setState('credential_server', adminServer.toString());
    setState('credential_token', adminToken);
    setState('credential_id', issued.credential.id);
  } else if (!legacyToken) {
    throw new Error('provide admin-server and admin-token for a short-lived credential, or the legacy token input');
  } else {
    mask(legacyToken);
    process.stdout.write('::warning::ngstone action is using the legacy token input; add admin-server and admin-token for automatic per-run credential revocation\n');
  }
  const repository = input('repository') || 'emilio-kariuki/ngstone';
  const version = input('version') || 'latest';
  validateRepository(repository);
  validateVersion(version);
  const binary = await downloadBinary(repository, version);
  const tunnel = await startTunnel(binary, target, token, server, transport, serverName, subdomain, input('host-header'), ttl, input('wait-timeout'), input('insecure'));
  const publicURL = validatePublicURL(tunnel.url);
  setOutput('url', publicURL);
  setOutput('pid', tunnel.pid);
  setState('log_path', tunnel.logPath);
  appendFile(process.env.GITHUB_ENV, `NGSTONE_URL=${publicURL}\nNGSTONE_PID=${tunnel.pid}\nNGSTONE_LOG=${tunnel.logPath}\n`);
  process.stdout.write(`ngstone tunnel ready: ${publicURL}\n`);
  const command = input('command');
  if (command) {
    const result = spawnSync('/bin/bash', ['-euo', 'pipefail', '-c', command], { env: { ...process.env, NGSTONE_URL: publicURL, NGSTONE_PID: String(tunnel.pid), NGSTONE_LOG: tunnel.logPath }, stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`command exited with status ${result.status}`);
  }
}

main().catch((error) => {
  process.stderr.write(`ngstone action failed: ${error.message}\n`);
  process.exitCode = 1;
});
