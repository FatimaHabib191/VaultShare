// Small strict schema validator. Unknown fields are rejected, strings are
// normalised (NFC, trimmed, control characters refused) and every failure is
// reported as { field, rule, message } so the client can explain it.
import { AppError } from '../lib/errors.js';

const CONTROL = /[\u0000-\u001F\u007F‪-‮⁦-⁩]/;
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const err = (field, rule, message) => ({ field, rule, message });

export const v = {
  str: ({ min = 1, max = 200, pattern, patternMsg, multiline = false } = {}) => (val, field) => {
    if (typeof val !== 'string') return [err(field, 'TYPE', 'must be text')];
    const s = val.normalize('NFC').trim();
    if (!multiline && CONTROL.test(s)) return [err(field, 'CONTROL_CHARS', 'contains control or direction-override characters')];
    if (s.length < min) return [err(field, 'TOO_SHORT', `must be at least ${min} characters`)];
    if (s.length > max) return [err(field, 'TOO_LONG', `must be at most ${max} characters`)];
    if (pattern && !pattern.test(s)) return [err(field, 'PATTERN', patternMsg || 'has an invalid format')];
    return { value: s };
  },
  password: ({ min = 10, max = 256 } = {}) => (val, field) => {
    if (typeof val !== 'string') return [err(field, 'TYPE', 'must be text')];
    if (val.length < min || val.length > max) return [err(field, 'LENGTH', `must be ${min}–${max} characters`)];
    return { value: val };
  },
  int: ({ min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = {}) => (val, field) => {
    if (!Number.isInteger(val)) return [err(field, 'TYPE', 'must be a whole number')];
    if (val < min || val > max) return [err(field, 'OUT_OF_RANGE', `must be between ${min} and ${max}`)];
    return { value: val };
  },
  bool: () => (val, field) => (typeof val === 'boolean' ? { value: val } : [err(field, 'TYPE', 'must be true or false')]),
  oneOf: (values) => (val, field) => (values.includes(val) ? { value: val } : [err(field, 'ENUM', `must be one of: ${values.join(', ')}`)]),
  uuid: () => (val, field) => (typeof val === 'string' && UUID_RE.test(val) ? { value: val } : [err(field, 'UUID', 'must be a valid identifier')]),
  hex: (len, max) => (val, field) => {
    const re = max == null ? new RegExp(`^[0-9a-f]{${len}}$`) : new RegExp(`^(?:[0-9a-f]{2}){${len / 2},${max / 2}}$`);
    return typeof val === 'string' && re.test(val) ? { value: val } : [err(field, 'HEX', max == null ? `must be ${len} lowercase hex characters` : `must be ${len}–${max} lowercase hex characters`)];
  },
  /** Nested object validated with the same strict rules (unknown fields rejected). */
  object: (schema) => (val, field) => {
    if (!val || typeof val !== 'object' || Array.isArray(val)) return [err(field, 'TYPE', 'must be an object')];
    const errors = [];
    const out = {};
    for (const [k, rule] of Object.entries(schema)) {
      if (val[k] === undefined && !rule.optional) {
        errors.push(err(`${field}.${k}`, 'REQUIRED', 'is required'));
        continue;
      }
      const r = rule(val[k], `${field}.${k}`);
      if (Array.isArray(r)) errors.push(...r);
      else if (r.value !== undefined) out[k] = r.value;
    }
    for (const k of Object.keys(val)) if (!(k in schema)) errors.push(err(`${field}.${k}`, 'UNKNOWN_FIELD', 'is not an accepted field'));
    return errors.length ? errors : { value: out };
  },
  b64: ({ minBytes = 1, maxBytes, exactBytes } = {}) => (val, field) => {
    if (typeof val !== 'string' || val.length % 4 !== 0 || !B64.test(val)) return [err(field, 'BASE64', 'must be standard base64')];
    const pad = val.endsWith('==') ? 2 : val.endsWith('=') ? 1 : 0;
    const bytes = (val.length / 4) * 3 - pad;
    if (exactBytes != null && bytes !== exactBytes) return [err(field, 'LENGTH', `must decode to exactly ${exactBytes} bytes`)];
    if (bytes < minBytes) return [err(field, 'TOO_SHORT', `must decode to at least ${minBytes} bytes`)];
    if (maxBytes != null && bytes > maxBytes) return [err(field, 'TOO_LONG', `must decode to at most ${maxBytes} bytes`)];
    return { value: val, bytes };
  },
  any: () => (val) => ({ value: val }),
  optional: (rule) => {
    const f = (val, field) => (val === undefined || val === null ? { value: undefined } : rule(val, field));
    f.optional = true;
    return f;
  },
};

/** Validate `body` against `schema`; throws VALIDATION_FAILED with per-field details. */
export function validate(schema, body, { allowUnknown = false } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new AppError('VALIDATION_FAILED', { details: [err('body', 'TYPE', 'must be a JSON object')] });
  }
  const errors = [];
  const out = {};
  const meta = {};
  for (const [field, rule] of Object.entries(schema)) {
    if (body[field] === undefined && !rule.optional) {
      errors.push(err(field, 'REQUIRED', 'is required'));
      continue;
    }
    const r = rule(body[field], field);
    if (Array.isArray(r)) errors.push(...r);
    else {
      if (r.value !== undefined) out[field] = r.value;
      if (r.bytes !== undefined) meta[field] = r.bytes;
    }
  }
  if (!allowUnknown) {
    for (const k of Object.keys(body)) if (!(k in schema)) errors.push(err(k, 'UNKNOWN_FIELD', 'is not an accepted field'));
  }
  if (errors.length) throw new AppError('VALIDATION_FAILED', { details: errors.slice(0, 20) });
  Object.defineProperty(out, '_bytes', { value: meta, enumerable: false });
  return out;
}

export const USERNAME = { min: 3, max: 32, pattern: /^[a-z][a-z0-9._-]{2,31}$/, patternMsg: 'use 3–32 lowercase letters, digits, dot, dash or underscore, starting with a letter' };

/** Sanitise a client-supplied filename for display. Never used as a filesystem path. */
export function sanitizeFilename(name) {
  const base = String(name).split(/[\\/]/).pop().normalize('NFC').trim();
  if (!base || CONTROL.test(base) || base.length > 120 || base.startsWith('.')) return null;
  if (/[<>:"|?*]/.test(base)) return null;
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(base);
  if (!m) return null;
  const parts = base.split('.');
  // reject double extensions that hide an executable type, e.g. report.pdf.exe or invoice.exe.pdf
  if (parts.slice(1, -1).some((p) => /^(exe|bat|cmd|com|js|vbs|ps1|scr|msi|sh|html?|svg)$/i.test(p))) return null;
  return { name: base, extension: m[1].toLowerCase() };
}
