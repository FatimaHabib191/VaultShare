// Thin fetch wrapper: JSON in/out, CSRF header on every state-changing call,
// errors normalised to ApiError { code, message, details, decision }.
let csrf = null;
let onAuthLost = () => {};

export const setCsrf = (t) => (csrf = t);
export const setAuthLostHandler = (fn) => (onAuthLost = fn);

export class ApiError extends Error {
  constructor(status, body) {
    const e = body?.error || {};
    super(e.message || `Request failed (${status})`);
    this.status = status;
    this.code = e.code || 'NETWORK_ERROR';
    this.details = e.details;
    this.decision = e.decision;
    this.requestId = e.requestId;
    this.retryAfter = e.retryAfter;
  }
}

export async function api(method, path, body) {
  const headers = { Accept: 'application/json' };
  const opts = { method, headers, credentials: 'same-origin' };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (csrf) headers['X-CSRF-Token'] = csrf;
    opts.body = JSON.stringify(body ?? {});
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch {
    throw new ApiError(0, { error: { code: 'NETWORK_ERROR', message: 'The server could not be reached. Check that VaultShare is running.' } });
  }
  const isJson = (res.headers.get('content-type') || '').includes('json');
  const data = isJson ? await res.json() : await res.text();
  if (!res.ok) {
    const err = new ApiError(res.status, isJson ? data : null);
    if ((err.code === 'AUTH_REQUIRED' || err.code === 'SESSION_EXPIRED') && !path.startsWith('/api/auth/')) onAuthLost(err);
    throw err;
  }
  return data;
}

export const get = (p) => api('GET', p);
export const post = (p, b) => api('POST', p, b);
export const put = (p, b) => api('PUT', p, b);
export const del = (p, b) => api('DELETE', p, b);

/** Fetch an export as a file (keeps the session cookie; no CSRF needed for GET). */
export async function fetchFile(path) {
  const res = await fetch(path, { credentials: 'same-origin' });
  if (!res.ok) throw new ApiError(res.status, await res.json().catch(() => null));
  const cd = res.headers.get('content-disposition') || '';
  const name = /filename="([^"]+)"/.exec(cd)?.[1] || 'vaultshare-export';
  return { blob: await res.blob(), name };
}
