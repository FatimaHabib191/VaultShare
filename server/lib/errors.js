// Stable error codes. Clients and tests rely on `code`; messages are safe for display
// and never contain stack traces, SQL or internal identifiers.
export const ERR = {
  VALIDATION_FAILED: { status: 400, message: 'The request did not pass validation.' },
  MALFORMED_JSON: { status: 400, message: 'The request body is not valid JSON.' },
  AUTH_REQUIRED: { status: 401, message: 'Sign in to continue.' },
  AUTH_FAILED: { status: 401, message: 'Username or password is incorrect.' },
  SESSION_EXPIRED: { status: 401, message: 'Your session expired. Sign in again.' },
  ENROLLMENT_INVALID: { status: 400, message: 'The enrollment code is invalid or has expired.' },
  CSRF_FAILED: { status: 403, message: 'The request was rejected because its security token is missing or invalid.' },
  FORBIDDEN: { status: 403, message: 'You do not have permission to perform this action.' },
  POLICY_DENIED: { status: 403, message: 'Access was denied by policy.' },
  NOT_FOUND: { status: 404, message: 'The requested item was not found.' },
  CONFLICT: { status: 409, message: 'The request conflicts with the current state.' },
  PAYLOAD_TOO_LARGE: { status: 413, message: 'The upload is larger than the configured limit.' },
  UNSUPPORTED_TYPE: { status: 415, message: 'This file type is not allowed.' },
  RATE_LIMITED: { status: 429, message: 'Too many requests. Wait a moment and try again.' },
  INTERNAL_ERROR: { status: 500, message: 'Something went wrong on the server. The event was logged.' },
};

export class AppError extends Error {
  constructor(code, { message, details, decision, retryAfter } = {}) {
    const def = ERR[code] || ERR.INTERNAL_ERROR;
    super(message || def.message);
    this.code = ERR[code] ? code : 'INTERNAL_ERROR';
    this.status = def.status;
    this.details = details;
    this.decision = decision;
    this.retryAfter = retryAfter;
    this.expose = true;
  }
}

export const fail = (code, opts) => {
  throw new AppError(code, opts);
};
