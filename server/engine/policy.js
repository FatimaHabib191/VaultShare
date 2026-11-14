// Policy engine: pure, side-effect-free functions. Each returns an explainable
// decision object that is stored verbatim with the result:
//   { decision: 'allow'|'deny', rule, reason, evidence, engine }
// Rules are evaluated in a fixed, documented order; the first failing rule wins.

import { checkContent } from '../../shared/content-sniff.js';

export const ENGINE_VERSION = 'vaultshare-policy/1.1.0';

export const RULES = {
  // download / access
  ALLOW_OWNER: 'Requester owns the document; owner grant is valid.',
  ALLOW_GRANT: 'Requester holds an active, unexpired grant with downloads remaining.',
  NO_GRANT: 'Requester has no grant for this document.',
  DOCUMENT_UNAVAILABLE: 'The document was deleted or never finished uploading.',
  GRANT_REVOKED: 'The grant was revoked.',
  GRANT_EXPIRED: 'The grant passed its expiry time.',
  DOWNLOAD_LIMIT_REACHED: 'The grant has no downloads remaining.',
  KEY_MISMATCH: "The requester's key pair changed after this grant was issued; the wrapped key cannot be opened.",
  ACCOUNT_INACTIVE: 'The requester account is not active.',
  // grant creation
  ALLOW_SHARE: 'Share request satisfies every sharing rule.',
  NOT_OWNER: 'Only the document owner can share it.',
  RECIPIENT_INVALID: 'Recipient does not exist, is not active or has not enrolled a key.',
  RECIPIENT_IS_OWNER: 'A document cannot be shared with its own owner.',
  RECIPIENT_ROLE_NOT_ALLOWED: 'Administrators cannot receive documents (they hold no document keys by design).',
  RECIPIENT_KEY_CHANGED: "The recipient's key fingerprint does not match the key the share was encrypted for.",
  WRAPPED_KEY_INVALID: 'The wrapped document key has the wrong length for the recipient key.',
  GRANT_TTL_OUT_OF_RANGE: 'Requested expiry is outside the configured limits.',
  DOWNLOAD_LIMIT_OUT_OF_RANGE: 'Requested download limit is outside the configured limits.',
  DUPLICATE_ACTIVE_GRANT: 'The recipient already holds an active grant for this document.',
  // upload
  ALLOW_UPLOAD: 'File type, size and ciphertext structure are valid.',
  TYPE_NOT_ALLOWED: 'The file extension or MIME type is not in the allowed list.',
  CONTENT_TYPE_MISMATCH: "The file's contents do not match its name (checked from its first bytes).",
  FILE_TOO_LARGE: 'The file exceeds the configured size limit.',
  FILE_EMPTY: 'The file is empty.',
  CIPHERTEXT_MALFORMED: 'The encrypted container failed structural validation.',
  CIPHERTEXT_LENGTH_MISMATCH: 'Ciphertext length does not match the declared plaintext size plus GCM overhead.',
  ALREADY_UPLOADED: 'Content for this document was already uploaded.',
};

// Severity and recommended action for every rule, so each result says how
// serious it is and what the person should do next.
//   info = expected outcome; low = user error; medium = policy limit reached;
//   high = possible attack or integrity problem that an administrator should review.
export const RULE_META = {
  ALLOW_OWNER: ['info', 'No action needed.'],
  ALLOW_GRANT: ['info', 'No action needed. Your copy is watermarked to you; do not redistribute it.'],
  ALLOW_SHARE: ['info', 'Confirm the recipient fingerprint with them out of band for sensitive files.'],
  ALLOW_UPLOAD: ['info', 'Share the file with the people who need it.'],
  NO_GRANT: ['medium', 'Ask the file owner to share it with you. Repeated attempts are reviewed by the administrator.'],
  DOCUMENT_UNAVAILABLE: ['low', 'The file was deleted or never finished uploading. Ask the owner for a new copy.'],
  GRANT_REVOKED: ['medium', 'Contact the file owner if you still need access.'],
  GRANT_EXPIRED: ['low', 'Ask the file owner to share it again.'],
  DOWNLOAD_LIMIT_REACHED: ['low', 'Ask the file owner for a new share with more downloads.'],
  KEY_MISMATCH: ['medium', 'Your key was reset. Ask the owner to revoke the old share and share again.'],
  ACCOUNT_INACTIVE: ['high', 'Contact your administrator.'],
  NOT_OWNER: ['high', 'Only the owner can share this file. Ask the owner to share it.'],
  RECIPIENT_INVALID: ['low', 'Choose an active person who has finished account setup.'],
  RECIPIENT_IS_OWNER: ['low', 'Choose a different recipient.'],
  RECIPIENT_ROLE_NOT_ALLOWED: ['low', 'Share with an operator or viewer; administrators cannot hold document keys.'],
  RECIPIENT_KEY_CHANGED: ['high', 'Reload and compare the fingerprint with the recipient before sharing again.'],
  WRAPPED_KEY_INVALID: ['high', 'Reload the page and try again. Report it if it repeats.'],
  GRANT_TTL_OUT_OF_RANGE: ['low', 'Choose a shorter expiry within the allowed maximum shown in the evidence.'],
  DOWNLOAD_LIMIT_OUT_OF_RANGE: ['low', 'Choose a download limit within the allowed maximum.'],
  DUPLICATE_ACTIVE_GRANT: ['low', 'The person already has access. Revoke the existing share first to change it.'],
  TYPE_NOT_ALLOWED: ['medium', 'Upload an allowed type (see evidence). Do not rename files to get around the check.'],
  CONTENT_TYPE_MISMATCH: ['high', 'Do not upload this file. Its contents are not what its name says; check where it came from.'],
  FILE_TOO_LARGE: ['low', 'Split or compress the file to fit the size limit.'],
  FILE_EMPTY: ['low', 'Choose a file that has content.'],
  CIPHERTEXT_MALFORMED: ['high', 'Upload again from the VaultShare page. Report it if it repeats.'],
  CIPHERTEXT_LENGTH_MISMATCH: ['high', 'Upload again from the VaultShare page. Report it if it repeats.'],
  ALREADY_UPLOADED: ['low', 'The file is already stored; no action needed.'],
  // client-side and other engines
  INTEGRITY_CHECK_FAILED: ['high', 'Do not trust this file. Report it to the administrator, who should verify the audit trail.'],
  CHAIN_INTACT: ['info', 'Export the audit trail and keep the head hash somewhere outside this machine.'],
  HASH_MISMATCH: ['high', 'Preserve the data folder, export the audit trail and investigate from the broken event.'],
  SEQUENCE_GAP: ['high', 'Events were deleted. Preserve the data folder and investigate.'],
  PREV_HASH_MISMATCH: ['high', 'Events were inserted or reordered. Preserve the data folder and investigate.'],
  TRUNCATED_BELOW_ANCHOR: ['high', 'Recent events were removed. Compare with your last exported head hash.'],
  ANCHOR_MISMATCH: ['high', 'The anchored event changed. Compare with your last exported head hash.'],
  WATERMARK_VERIFIED: ['high', 'Revoke the recipient\'s remaining shares and follow your leak-handling procedure.'],
  WATERMARK_FORGED: ['medium', 'The reference was altered; treat the copy as untraceable.'],
  WATERMARK_UNKNOWN: ['low', 'This reference did not come from this VaultShare instance.'],
  WATERMARK_MALFORMED: ['low', 'Paste the full reference that starts with VS1.'],
};

export function ruleMeta(rule) {
  const m = RULE_META[rule];
  return m ? { severity: m[0], recommendedAction: m[1] } : { severity: 'info', recommendedAction: 'No action needed.' };
}

const decide = (decision, rule, evidence = {}) => ({
  decision,
  rule,
  reason: RULES[rule],
  ...ruleMeta(rule),
  evidence,
  engine: ENGINE_VERSION,
});

const iso = (ms) => (ms == null ? null : new Date(ms).toISOString());

/**
 * Evaluate a download request.
 * @param {object} p { user, document, grant, now }
 *   grant: newest grant for (document, user) or null
 */
export function evaluateDownload({ user, document, grant, now }) {
  if (!user || user.status !== 'active') return decide('deny', 'ACCOUNT_INACTIVE', { userStatus: user?.status ?? null });
  if (!grant) return decide('deny', 'NO_GRANT', { documentId: document?.id ?? null });
  if (!document || document.status !== 'active') return decide('deny', 'DOCUMENT_UNAVAILABLE', { documentStatus: document?.status ?? null });
  const ev = {
    grantId: grant.id,
    isOwnerGrant: !!grant.is_owner,
    expiresAt: iso(grant.expires_at),
    evaluatedAt: iso(now),
    downloadsUsed: grant.download_count,
    downloadLimit: grant.max_downloads,
    grantKeyVersion: grant.recipient_key_version,
    currentKeyVersion: user.key_version,
  };
  if (grant.revoked_at) return decide('deny', 'GRANT_REVOKED', { ...ev, revokedAt: iso(grant.revoked_at) });
  if (grant.expires_at != null && now >= grant.expires_at) return decide('deny', 'GRANT_EXPIRED', ev);
  if (grant.max_downloads != null && grant.download_count >= grant.max_downloads) return decide('deny', 'DOWNLOAD_LIMIT_REACHED', ev);
  if (grant.recipient_key_version !== user.key_version || grant.recipient_key_fingerprint !== user.key_fingerprint) {
    return decide('deny', 'KEY_MISMATCH', { ...ev, grantFingerprint: grant.recipient_key_fingerprint.slice(0, 16), currentFingerprint: (user.key_fingerprint || '').slice(0, 16) });
  }
  return decide('allow', grant.is_owner ? 'ALLOW_OWNER' : 'ALLOW_GRANT', ev);
}

/**
 * Evaluate a share (grant creation) request.
 */
export function evaluateGrant({ actor, document, recipient, request, activeGrant, settings, wrappedKeyBytes }) {
  if (!document || document.status !== 'active') return decide('deny', 'DOCUMENT_UNAVAILABLE', {});
  if (document.owner_id !== actor.id) return decide('deny', 'NOT_OWNER', {});
  if (!recipient || recipient.status !== 'active' || !recipient.public_key) return decide('deny', 'RECIPIENT_INVALID', {});
  if (recipient.id === actor.id) return decide('deny', 'RECIPIENT_IS_OWNER', {});
  if (recipient.role === 'admin') return decide('deny', 'RECIPIENT_ROLE_NOT_ALLOWED', { recipientRole: recipient.role });
  const ev = {
    recipient: recipient.username,
    requestedMinutes: request.expiresInMinutes,
    maxMinutes: settings.max_grant_ttl_hours * 60,
    requestedDownloads: request.maxDownloads,
    maxDownloads: settings.max_downloads_cap,
  };
  if (request.recipientKeyFingerprint !== recipient.key_fingerprint) {
    return decide('deny', 'RECIPIENT_KEY_CHANGED', { ...ev, expected: (recipient.key_fingerprint || '').slice(0, 16), supplied: String(request.recipientKeyFingerprint).slice(0, 16) });
  }
  if (wrappedKeyBytes !== 256) return decide('deny', 'WRAPPED_KEY_INVALID', { ...ev, wrappedKeyBytes, expectedBytes: 256 });
  if (!Number.isInteger(request.expiresInMinutes) || request.expiresInMinutes < 1 || request.expiresInMinutes > ev.maxMinutes) {
    return decide('deny', 'GRANT_TTL_OUT_OF_RANGE', ev);
  }
  if (!Number.isInteger(request.maxDownloads) || request.maxDownloads < 1 || request.maxDownloads > settings.max_downloads_cap) {
    return decide('deny', 'DOWNLOAD_LIMIT_OUT_OF_RANGE', ev);
  }
  if (activeGrant) return decide('deny', 'DUPLICATE_ACTIVE_GRANT', { ...ev, existingGrantId: activeGrant.id });
  return decide('allow', 'ALLOW_SHARE', ev);
}

/**
 * Evaluate the metadata half of an upload (before content arrives).
 */
export function evaluateUploadMeta({ extension, mimeType, sizeBytes, settings, supported, content }) {
  const ev = { extension, mimeType, sizeBytes, maxBytes: settings.max_file_size_mb * 1024 * 1024, allowed: settings.allowed_extensions };
  const t = supported[extension];
  if (!t || !settings.allowed_extensions.includes(extension) || t.mime !== mimeType) return decide('deny', 'TYPE_NOT_ALLOWED', ev);
  if (content) {
    const c = checkContent(extension, content);
    ev.detectedContent = c.detected;
    ev.firstBytes = content.headHex;
    if (!c.ok) return { ...decide('deny', 'CONTENT_TYPE_MISMATCH', { ...ev, expectedContent: c.expected }), reason: c.message };
  }
  if (sizeBytes <= 0) return decide('deny', 'FILE_EMPTY', ev);
  if (sizeBytes > ev.maxBytes) return decide('deny', 'FILE_TOO_LARGE', ev);
  return decide('allow', 'ALLOW_UPLOAD', ev);
}

/**
 * Evaluate the ciphertext half of an upload.
 */
export function evaluateUploadContent({ document, parsed, ciphertextBytes, overhead, wrappedKeyBytes }) {
  const ev = { declaredSize: document.size_plain, ciphertextBytes, expectedBytes: document.size_plain + overhead };
  if (document.status !== 'pending') return decide('deny', 'ALREADY_UPLOADED', { status: document.status });
  if (!parsed.ok) return decide('deny', 'CIPHERTEXT_MALFORMED', { ...ev, check: parsed.reason });
  if (ciphertextBytes !== ev.expectedBytes) return decide('deny', 'CIPHERTEXT_LENGTH_MISMATCH', ev);
  if (wrappedKeyBytes !== 256) return decide('deny', 'WRAPPED_KEY_INVALID', { ...ev, wrappedKeyBytes, expectedBytes: 256 });
  return decide('allow', 'ALLOW_UPLOAD', { ...ev, containerVersion: parsed.version });
}
