// sync-token.js - ZCode credential -> plan-jwt.json
//
// Supports both credential store formats written by the ZCode desktop client:
//
//   enc:v1:<ivB64>.<tagB64>.<ctB64>
//       AES-256-GCM, key = SHA-256("zcode-credential-fallback:<os>:<home>:<user>")
//
//   enc:v2:<source>:<fingerprint>:<ivB64>.<tagB64>.<ctB64>
//       AES-256-GCM, key = the raw 32-byte secret held by the OS credential
//       store, entry "<fingerprint>.ZCode Credential Encryption" (base64url).
//       `source` is "os" when keyed from the OS store, "env" when pinned to a
//       managed secret (ZCODE_CREDENTIAL_SECRET[_FILE]).
//
// A bad key surfaces as "unable to authenticate data"; we treat that as an
// error instead of silently forwarding ciphertext upstream (which produced
// the opaque `upstream 401` seen in 9Router).

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const LEGACY_PREFIX = 'enc:v1:';
const V2_PREFIX = 'enc:v2:';

function digest(s) {
  return crypto.createHash('sha256').update(s).digest();
}

// ---- enc:v1 ---------------------------------------------------------------

function legacyKeyCandidates(env = process.env) {
  const user = (() => { try { return os.userInfo().username; } catch { return 'unknown'; } })();
  const fallback = `zcode-credential-fallback:${os.platform()}:${os.homedir()}:${user}`;
  const secret = env.ZCODE_CREDENTIAL_SECRET;
  return [...new Set([secret || fallback, (secret || '').trim() || fallback, fallback])].map(digest);
}

function openV1(payload, key) {
  const [ivB64, tagB64, dataB64] = payload.split('.');
  const iv = Buffer.from(ivB64, 'base64url');
  const tag = Buffer.from(tagB64, 'base64url');
  const data = Buffer.from(dataB64, 'base64url');
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: tag.length });
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
}

// ---- enc:v2 key from the OS credential store ------------------------------

// The Credential Manager entry is named after the full sha256 hex of the
// credentials.json path. The v2 payload's own "fingerprint" segment is
// sha256(keyBytes)[0:24] and is only used to verify we picked the right key.
function credentialTarget(credPath) {
  return crypto.createHash('sha256').update(credPath).digest('hex') +
    '.ZCode Credential Encryption';
}

function fingerprintOf(keyBytes) {
  return crypto.createHash('sha256').update(keyBytes).digest('hex').slice(0, 24);
}

function readWindowsKey(credPath) {
  // Credential Manager entry; blob is a UTF-16LE base64url secret
  // (32 bytes decoded). Delegated to read-zcode-key.ps1 so the C# interop
  // stays quoting-safe.
  const { execFileSync } = require('child_process');
  const helper = path.join(__dirname, 'read-zcode-key.ps1');
  if (!fs.existsSync(helper)) throw new Error('read-zcode-key.ps1 not found next to sync-token.js');
  const out = execFileSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper,
      '-Target', credentialTarget(credPath)],
    { encoding: 'utf8', windowsHide: true }
  );
  return out.trim();
}

function osKeyCandidates(fingerprint, env = process.env, credPath) {
  const keys = [];
  // managed secret wins when pinned
  const managed = env.ZCODE_CREDENTIAL_SECRET;
  if (managed) keys.push(digest(managed));
  if (env.ZCODE_CREDENTIAL_SECRET_FILE) {
    try {
      keys.push(digest(fs.readFileSync(env.ZCODE_CREDENTIAL_SECRET_FILE, 'utf8').trim()));
    } catch { /* ignore */ }
  }
  if (process.platform === 'win32' && credPath) {
    try {
      const raw = readWindowsKey(credPath);
      if (raw) keys.push(Buffer.from(raw, 'base64url'));
    } catch (e) {
      console.error('[sync-token] Credential Manager read failed:', e.message);
    }
  }
  const usable = keys.filter((k) => k && k.length === 32);
  if (fingerprint) {
    const match = usable.filter((k) => fingerprintOf(k) === fingerprint);
    if (match.length) return match; // strongest signal first
  }
  return usable;
}

// ---- decrypt dispatcher ---------------------------------------------------

function decrypt(value, env = process.env, credPath) {
  if (value.startsWith(LEGACY_PREFIX)) {
    const payload = value.slice(LEGACY_PREFIX.length);
    for (const key of legacyKeyCandidates(env)) {
      try { return openV1(payload, key); } catch { /* next */ }
    }
    throw new Error('enc:v1 decrypt failed (no key candidate matched)');
  }

  if (value.startsWith(V2_PREFIX)) {
    // enc:v2:<source>:<fingerprint>:<iv>.<tag>.<ct>
    const rest = value.slice(V2_PREFIX.length);
    const first = rest.indexOf(':');
    if (first < 0) throw new Error('malformed enc:v2 value');
    const source = rest.slice(0, first);
    const afterSource = rest.slice(first + 1);
    const second = afterSource.indexOf(':');
    if (second < 0) throw new Error('malformed enc:v2 value');
    const fingerprint = afterSource.slice(0, second);
    const payload = afterSource.slice(second + 1);

    if (source === 'env') {
      // pinned to a managed secret; same AES-GCM payload layout
      for (const key of osKeyCandidates('', env, credPath)) {
        try { return openV1(payload, key); } catch { /* next */ }
      }
      throw new Error('enc:v2:env decrypt failed (check ZCODE_CREDENTIAL_SECRET)');
    }

    const keys = osKeyCandidates(fingerprint, env, credPath);
    if (!keys.length) throw new Error('enc:v2:os has no usable OS credential store key');
    for (const key of keys) {
      try { return openV1(payload, key); } catch { /* next */ }
    }
    throw new Error('enc:v2:os decrypt failed (OS key did not authenticate)');
  }

  return value; // plaintext
}

// ---- main -----------------------------------------------------------------

function main() {
  const storeDir = process.env.ZCODE_STATE_DIR || path.join(os.homedir(), '.zcode', 'v2');
  const credPath = path.join(storeDir, 'credentials.json');
  if (!fs.existsSync(credPath)) {
    console.log('[sync-token] no credential store at', credPath);
    return 0;
  }

  const data = JSON.parse(fs.readFileSync(credPath, 'utf8'));
  const stored = data['zcodejwttoken'];
  if (!stored) {
    console.error('[sync-token] zcodejwttoken missing from store');
    return 1;
  }

  const jwt = decrypt(String(stored), process.env, credPath);
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    console.error('[sync-token] decrypted value is not a JWT (len=' + jwt.length + ')');
    return 1;
  }

  const outFile = process.env.ZCODE_PLAN_JWT_FILE || path.join(__dirname, 'plan-jwt.json');
  // No BOM: Go's json.Unmarshal on the bridge rejects a UTF-8 BOM.
  fs.writeFileSync(outFile, JSON.stringify({ jwt }), { encoding: 'utf8' });
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  console.log('[sync-token] OK ->', outFile, '| sub=' + claims.sub + ' iat=' + claims.iat);
  return 0;
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (e) {
    console.error('[sync-token] error:', e.message);
    process.exitCode = 1;
  }
}

module.exports = { decrypt };
