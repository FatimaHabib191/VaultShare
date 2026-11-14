// Role-based permission matrix (least privilege). Enforced by the API layer on
// every route; the same table is used by the access-control matrix test (T3)
// and printed in the administrator guide.
//
//   admin    — manages users, settings and audit; cannot hold document keys, so it
//              can never read document content (separation of duties).
//   operator — encrypts and uploads documents, shares and revokes them, downloads
//              documents shared with them.
//   viewer   — restricted: can only download documents explicitly shared with them.

export const ROLES = ['admin', 'operator', 'viewer'];

export const ACTIONS = {
  'doc.upload': ['operator'],
  'doc.list': ['operator', 'viewer'],
  'doc.read_meta': ['operator', 'viewer'],
  'doc.download': ['operator', 'viewer'],
  'doc.delete': ['operator'],
  'grant.create': ['operator'],
  'grant.revoke': ['operator', 'admin'],
  'directory.read': ['operator'],
  'decision.read_own': ['admin', 'operator', 'viewer'],
  'decision.read_all': ['admin'],
  'report.export_own': ['admin', 'operator', 'viewer'],
  'report.export_all': ['admin'],
  'user.manage': ['admin'],
  'config.read': ['admin'],
  'config.write': ['admin'],
  'audit.read': ['admin'],
  'audit.verify': ['admin'],
  'audit.export': ['admin'],
  'watermark.trace': ['admin'],
};

export function can(role, action) {
  const allowed = ACTIONS[action];
  return Array.isArray(allowed) && allowed.includes(role);
}

export function matrix() {
  return Object.fromEntries(Object.keys(ACTIONS).map((a) => [a, Object.fromEntries(ROLES.map((r) => [r, can(r, a)]))]));
}
