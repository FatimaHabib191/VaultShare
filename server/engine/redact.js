// Removes secrets and bulky key material before anything is written to logs,
// decisions or exported reports.
const SECRET_KEYS = /^(password|newpassword|authkey|currentauthkey|newauthkey|secret|csrf|csrftoken|cookie|wrappedkey|wrappedprivatekey|ciphertext|privatekey|enrollmentcode|codehash|authhash|authsalt|sessiontoken|token|code|wrapiv)$/i;

export function redact(value, depth = 0) {
  if (depth > 6) return '[depth-limit]';
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEYS.test(k.replace(/[_-]/g, ''))) out[k] = '[redacted]';
      else out[k] = redact(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string' && value.length > 300) return `${value.slice(0, 300)}…[truncated]`;
  return value;
}
