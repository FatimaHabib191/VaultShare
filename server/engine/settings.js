// Administrator-configurable rules and thresholds. Every value has a type and
// hard bounds; changes are versioned (config_versions) and every decision stores
// the config version it was evaluated under, so results are reproducible.

export const SUPPORTED_TYPES = {
  txt: { mime: 'text/plain', kind: 'text' },
  md: { mime: 'text/markdown', kind: 'text' },
  csv: { mime: 'text/csv', kind: 'text' },
  pdf: { mime: 'application/pdf', kind: 'pdf' },
  png: { mime: 'image/png', kind: 'image' },
  jpg: { mime: 'image/jpeg', kind: 'image' },
  jpeg: { mime: 'image/jpeg', kind: 'image' },
};

export const SETTINGS_SCHEMA = {
  max_file_size_mb: { type: 'int', min: 1, max: 20, default: 10, label: 'Maximum file size (MB)' },
  allowed_extensions: {
    type: 'list',
    values: Object.keys(SUPPORTED_TYPES),
    default: ['txt', 'md', 'csv', 'pdf', 'png', 'jpg', 'jpeg'],
    label: 'Allowed file types',
  },
  max_grant_ttl_hours: { type: 'int', min: 1, max: 720, default: 168, label: 'Longest allowed share (hours)' },
  default_grant_ttl_hours: { type: 'int', min: 1, max: 720, default: 24, label: 'Default share length (hours)' },
  max_downloads_cap: { type: 'int', min: 1, max: 100, default: 10, label: 'Most downloads per share' },
  session_idle_minutes: { type: 'int', min: 5, max: 240, default: 30, label: 'Sign out after inactivity (minutes)' },
  session_absolute_hours: { type: 'int', min: 1, max: 24, default: 8, label: 'Longest session (hours)' },
  login_attempts_per_15min: { type: 'int', min: 3, max: 50, default: 10, label: 'Sign-in attempts per 15 minutes' },
  sensitive_actions_per_min: { type: 'int', min: 5, max: 300, default: 30, label: 'Uploads, shares and downloads per minute' },
  kdf_iterations: { type: 'int', min: 100000, max: 2000000, default: 600000, label: 'Password key-derivation rounds (new enrollments)' },
  enrollment_code_hours: { type: 'int', min: 1, max: 168, default: 24, label: 'Enrollment code lifetime (hours)' },
};

export function defaultSettings(env = {}) {
  const s = {};
  for (const [k, def] of Object.entries(SETTINGS_SCHEMA)) s[k] = Array.isArray(def.default) ? [...def.default] : def.default;
  if (env.testMode) s.kdf_iterations = 1000; // fast tests only; bounds are relaxed in test mode
  return s;
}

/** Validate a partial change set. Returns { ok, errors, next } */
export function validateSettingsChange(current, changes, { testMode = false } = {}) {
  const errors = [];
  const next = { ...current };
  if (!changes || typeof changes !== 'object' || Array.isArray(changes)) {
    return { ok: false, errors: [{ field: 'changes', rule: 'TYPE', message: 'changes must be an object' }] };
  }
  for (const [key, value] of Object.entries(changes)) {
    const def = SETTINGS_SCHEMA[key];
    if (!def) {
      errors.push({ field: key, rule: 'UNKNOWN_SETTING', message: 'Unknown setting' });
      continue;
    }
    if (def.type === 'int') {
      const min = testMode && key === 'kdf_iterations' ? 1000 : def.min;
      if (!Number.isInteger(value) || value < min || value > def.max) {
        errors.push({ field: key, rule: 'OUT_OF_RANGE', message: `${def.label} must be a whole number from ${min} to ${def.max}` });
        continue;
      }
    } else if (def.type === 'list') {
      if (!Array.isArray(value) || value.length === 0 || value.some((v) => !def.values.includes(v)) || new Set(value).size !== value.length) {
        errors.push({ field: key, rule: 'INVALID_LIST', message: `${def.label} must be a non-empty subset of ${def.values.join(', ')}` });
        continue;
      }
    }
    next[key] = value;
  }
  if (next.default_grant_ttl_hours > next.max_grant_ttl_hours) {
    errors.push({ field: 'default_grant_ttl_hours', rule: 'DEFAULT_EXCEEDS_MAX', message: 'Default share length cannot exceed the longest allowed share' });
  }
  return { ok: errors.length === 0, errors, next };
}

export function diffSettings(before, after) {
  const diff = {};
  for (const k of Object.keys(SETTINGS_SCHEMA)) {
    if (JSON.stringify(before[k]) !== JSON.stringify(after[k])) diff[k] = { from: before[k], to: after[k] };
  }
  return diff;
}
