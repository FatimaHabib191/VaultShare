// FR-2 (AES-GCM encryption), FR-3 (key wrapping), FR-4 (expiry/revocation), FR-5 (watermark issue).
// The server only ever handles ciphertext and wrapped keys; it validates their
// structure, enforces policy, and records an explainable decision for each step.
import { Router } from 'express';
import { randomUUID, createHash } from 'node:crypto';
import { AppError } from '../../lib/errors.js';
import { validate, v, sanitizeFilename, UUID_RE } from '../../engine/validation.js';
import { evaluateUploadMeta, evaluateUploadContent, evaluateGrant, evaluateDownload } from '../../engine/policy.js';
import { SUPPORTED_TYPES } from '../../engine/settings.js';
import { issuePayload, label as wmLabel } from '../../engine/watermark.js';
import { requirePerm, asyncH } from '../middleware.js';
import { parseContainer, documentBinding, fromB64, toB64, CONTAINER_OVERHEAD_BYTES } from '../../../shared/crypto-core.js';

const WRAPPED_DEK = v.b64({ minBytes: 1, maxBytes: 1024 });

function docView(d) {
  return {
    id: d.id,
    filename: d.filename,
    extension: d.extension,
    mimeType: d.mime_type,
    sizeBytes: d.size_plain,
    cipherBytes: d.size_cipher,
    cipherSha256: d.cipher_sha256,
    status: d.status,
    ownerId: d.owner_id,
    ownerName: d.owner_name,
    createdAt: d.created_at && new Date(d.created_at).toISOString(),
    uploadedAt: d.uploaded_at && new Date(d.uploaded_at).toISOString(),
  };
}

export function grantStatus(g, t, currentKeyVersion) {
  if (g.revoked_at) return 'revoked';
  if (g.expires_at != null && t >= g.expires_at) return 'expired';
  if (g.max_downloads != null && g.download_count >= g.max_downloads) return 'exhausted';
  if (currentKeyVersion != null && g.recipient_key_version !== currentKeyVersion) return 'key_mismatch';
  return 'active';
}

function grantView(g, t) {
  return {
    id: g.id,
    recipientId: g.recipient_id,
    recipientName: g.recipient_name,
    isOwner: !!g.is_owner,
    status: grantStatus(g, t, g.current_key_version),
    expiresAt: g.expires_at ? new Date(g.expires_at).toISOString() : null,
    maxDownloads: g.max_downloads,
    downloadCount: g.download_count,
    revokedAt: g.revoked_at ? new Date(g.revoked_at).toISOString() : null,
    revokedBy: g.revoked_by_name ?? null,
    revokeReason: g.revoke_reason ?? null,
    keyFingerprint: g.recipient_key_fingerprint,
    createdAt: new Date(g.created_at).toISOString(),
  };
}

export default function documentRoutes(svc, limit) {
  const r = Router();
  const sensitive = limit('sensitive', { windowMs: 60_000, limitFn: () => svc.settings().sensitive_actions_per_min, keyFn: (req) => req.user.id });

  const idParam = (req) => {
    if (!UUID_RE.test(req.params.id)) throw new AppError('NOT_FOUND');
    return req.params.id;
  };

  // ---- list
  r.get('/', requirePerm('doc.list'), (req, res) => {
    const t = svc.now();
    const owned = req.user.role === 'operator' ? svc.repos.documents.owned(req.user.id).map((d) => ({ ...docView(d), activeShares: d.active_shares })) : [];
    const shared = svc.repos.documents.sharedWith(req.user.id).map((d) => ({
      ...docView(d),
      grant: {
        id: d.grant_id,
        status: d.status !== 'active' ? 'document_deleted' : grantStatus(d, t, req.user.key_version),
        expiresAt: d.expires_at ? new Date(d.expires_at).toISOString() : null,
        maxDownloads: d.max_downloads,
        downloadCount: d.download_count,
        sharedAt: new Date(d.shared_at).toISOString(),
      },
    }));
    res.json({ owned, shared });
  });

  // ---- current upload/share limits, so the interface can state the real rules
  r.get('/policy', requirePerm('doc.list'), (req, res) => {
    const c = svc.settings();
    res.json({
      allowedExtensions: c.allowed_extensions,
      maxFileSizeMb: c.max_file_size_mb,
      maxGrantHours: c.max_grant_ttl_hours,
      defaultGrantHours: c.default_grant_ttl_hours,
      maxDownloads: c.max_downloads_cap,
      settingsVersion: svc.settingsVersion(),
    });
  });

  // ---- upload step 1: declare metadata, receive server-generated id + AAD binding
  r.post('/', requirePerm('doc.upload'), sensitive, (req, res) => {
    const started = performance.now();
    const body = validate(
      {
        filename: v.str({ min: 3, max: 120 }),
        mimeType: v.str({ max: 100 }),
        sizeBytes: v.int({ min: 0, max: 1024 * 1024 * 1024 }),
        // first bytes + UTF-8 facts measured in the browser before encryption (no file contents)
        content: v.object({ headHex: v.hex(0, 16), utf8: v.bool(), hasNul: v.bool() }),
      },
      req.body
    );
    const fn = sanitizeFilename(body.filename);
    const cfg = svc.settings();
    const decision = fn
      ? evaluateUploadMeta({ extension: fn.extension, mimeType: body.mimeType, sizeBytes: body.sizeBytes, settings: cfg, supported: SUPPORTED_TYPES, content: body.content })
      : { decision: 'deny', rule: 'TYPE_NOT_ALLOWED', reason: 'The filename is unsafe or has no recognised extension.', evidence: { filename: body.filename.slice(0, 60) }, engine: 'vaultshare-policy/1.0.0' };
    const rec = svc.decide(req, { action: 'upload', subjectType: 'document', subjectLabel: fn?.name ?? body.filename.slice(0, 60) }, decision, started);
    if (decision.decision === 'deny') {
      req.audit('DOC_UPLOAD_REJECTED', 'denied', { details: { filename: fn?.name ?? body.filename.slice(0, 60), rule: decision.rule, severity: decision.severity, detected: decision.evidence?.detectedContent ?? null, decisionId: rec.id } });
      throw new AppError(decision.rule === 'FILE_TOO_LARGE' ? 'PAYLOAD_TOO_LARGE' : ['TYPE_NOT_ALLOWED', 'CONTENT_TYPE_MISMATCH'].includes(decision.rule) ? 'UNSUPPORTED_TYPE' : 'VALIDATION_FAILED', { decision: rec });
    }
    const id = randomUUID();
    const binding = documentBinding(id, req.user.id);
    svc.repos.documents.create({
      id,
      owner_id: req.user.id,
      filename: fn.name,
      extension: fn.extension,
      mime_type: body.mimeType,
      size_plain: body.sizeBytes,
      binding,
      config_version: svc.settingsVersion(),
    });
    req.audit('DOC_INIT', 'success', { targetType: 'document', targetId: id, details: { filename: fn.name, sizeBytes: body.sizeBytes } });
    res.status(201).json({ id, binding, decision: rec });
  });

  // ---- upload step 2: ciphertext + owner's wrapped DEK
  r.put(
    '/:id/content',
    requirePerm('doc.upload'),
    sensitive,
    (req, res) => {
      const started = performance.now();
      const id = idParam(req);
      const doc = svc.repos.documents.byId(id);
      if (!doc || doc.owner_id !== req.user.id) throw new AppError('NOT_FOUND');
      const maxB = svc.settings().max_file_size_mb * 1024 * 1024 + CONTAINER_OVERHEAD_BYTES;
      const body = validate({ ciphertext: v.b64({ minBytes: 1, maxBytes: maxB }), wrappedKey: WRAPPED_DEK }, req.body);
      const bytes = fromB64(body.ciphertext);
      const decision = evaluateUploadContent({
        document: doc,
        parsed: parseContainer(bytes),
        ciphertextBytes: bytes.length,
        overhead: CONTAINER_OVERHEAD_BYTES,
        wrappedKeyBytes: body._bytes.wrappedKey,
      });
      const rec = svc.decide(req, { action: 'upload_content', subjectType: 'document', subjectId: id, subjectLabel: doc.filename }, decision, started);
      if (decision.decision === 'deny') {
        req.audit('DOC_UPLOAD_REJECTED', 'denied', { targetType: 'document', targetId: id, details: { rule: decision.rule, decisionId: rec.id } });
        throw new AppError(decision.rule === 'ALREADY_UPLOADED' ? 'CONFLICT' : 'VALIDATION_FAILED', { decision: rec });
      }
      const sha = createHash('sha256').update(bytes).digest('hex');
      svc.repos.tx(() => {
        const ok = svc.repos.documents.activate({ id, content: Buffer.from(bytes), size_cipher: bytes.length, cipher_sha256: sha }).changes === 1;
        if (!ok) throw new AppError('CONFLICT');
        svc.repos.grants.create({
          id: randomUUID(),
          document_id: id,
          recipient_id: req.user.id,
          granted_by: req.user.id,
          is_owner: 1,
          wrapped_key: body.wrappedKey,
          recipient_key_fingerprint: req.user.key_fingerprint,
          recipient_key_version: req.user.key_version,
          expires_at: null,
          max_downloads: null,
          decision_id: rec.id,
        });
      });
      req.audit('DOC_UPLOAD', 'success', { targetType: 'document', targetId: id, details: { filename: doc.filename, cipherBytes: bytes.length, cipherSha256: sha, decisionId: rec.id } });
      res.json({ document: docView({ ...svc.repos.documents.byId(id) }), decision: rec });
    }
  );

  // ---- document detail (owner sees grants; recipients see their own grant only)
  r.get('/:id', requirePerm('doc.read_meta'), (req, res) => {
    const id = idParam(req);
    const doc = svc.repos.documents.byId(id);
    const t = svc.now();
    if (!doc || doc.status === 'pending') throw new AppError('NOT_FOUND');
    if (doc.owner_id === req.user.id) {
      return res.json({ document: docView(doc), isOwner: true, grants: svc.repos.grants.forDocument(id).map((g) => grantView(g, t)) });
    }
    const mine = svc.repos.grants.forDocument(id).filter((g) => g.recipient_id === req.user.id);
    if (!mine.length) {
      req.audit('ACCESS_DENIED', 'denied', { targetType: 'document', targetId: id, details: { permission: 'doc.read_meta', reason: 'no_grant' } });
      throw new AppError('NOT_FOUND');
    }
    res.json({ document: docView(doc), isOwner: false, grants: mine.map((g) => grantView(g, t)) });
  });

  // ---- delete (owner): crypto-shred ciphertext and wrapped keys
  r.delete('/:id', requirePerm('doc.delete'), (req, res) => {
    const id = idParam(req);
    validate({ confirm: v.oneOf([true]) }, req.body);
    const doc = svc.repos.documents.byId(id);
    if (!doc || doc.owner_id !== req.user.id || doc.status === 'deleted') throw new AppError('NOT_FOUND');
    let revoked = 0;
    svc.repos.tx(() => {
      revoked = svc.repos.grants.revokeAllForDocument(id, req.user.id, 'document deleted');
      svc.repos.documents.softDelete(id);
    });
    req.audit('DOC_DELETE', 'success', { targetType: 'document', targetId: id, details: { filename: doc.filename, grantsRevoked: revoked } });
    res.json({ ok: true, grantsRevoked: revoked });
  });

  // ---- owner's own wrapped DEK, needed in the browser to re-wrap it for a new recipient
  r.get('/:id/owner-key', requirePerm('grant.create'), (req, res) => {
    const id = idParam(req);
    const doc = svc.repos.documents.byId(id);
    if (!doc || doc.owner_id !== req.user.id || doc.status !== 'active') throw new AppError('NOT_FOUND');
    const g = svc.repos.grants.latestFor(id, req.user.id);
    const decision = evaluateDownload({ user: req.user, document: doc, grant: g, now: svc.now() });
    if (decision.decision === 'deny') throw new AppError('POLICY_DENIED', { message: decision.reason, decision });
    req.audit('DOC_KEY_ACCESS', 'success', { targetType: 'document', targetId: id, details: { purpose: 'share' } });
    res.json({ wrappedKey: g.wrapped_key, binding: doc.binding });
  });

  // ---- share: owner supplies the DEK wrapped to the recipient's public key
  r.post('/:id/grants', requirePerm('grant.create'), sensitive, (req, res) => {
    const started = performance.now();
    const id = idParam(req);
    const body = validate(
      {
        recipientId: v.uuid(),
        wrappedKey: WRAPPED_DEK,
        recipientKeyFingerprint: v.hex(64),
        expiresInMinutes: v.int({ min: 1, max: 720 * 60 }),
        maxDownloads: v.int({ min: 1, max: 100 }),
      },
      req.body
    );
    const doc = svc.repos.documents.byId(id);
    if (!doc || doc.owner_id !== req.user.id) {
      // do not reveal other users' documents
      req.audit('ACCESS_DENIED', 'denied', { targetType: 'document', targetId: id, details: { permission: 'grant.create', reason: 'not_owner_or_missing' } });
      throw new AppError('NOT_FOUND');
    }
    const recipient = svc.repos.users.byId(body.recipientId);
    const t = svc.now();
    const decision = evaluateGrant({
      actor: req.user,
      document: doc,
      recipient,
      request: body,
      activeGrant: recipient ? svc.repos.grants.activeFor(id, recipient.id, t) : null,
      settings: svc.settings(),
      wrappedKeyBytes: body._bytes.wrappedKey,
    });
    const rec = svc.decide(req, { action: 'share', subjectType: 'document', subjectId: id, subjectLabel: `${doc.filename} → ${recipient?.username ?? 'unknown'}` }, decision, started);
    if (decision.decision === 'deny') {
      req.audit('GRANT_DENIED', 'denied', { targetType: 'document', targetId: id, details: { rule: decision.rule, recipient: recipient?.username ?? null, decisionId: rec.id } });
      throw new AppError(decision.rule === 'DUPLICATE_ACTIVE_GRANT' ? 'CONFLICT' : 'POLICY_DENIED', { decision: rec });
    }
    const grantId = randomUUID();
    svc.repos.grants.create({
      id: grantId,
      document_id: id,
      recipient_id: recipient.id,
      granted_by: req.user.id,
      is_owner: 0,
      wrapped_key: body.wrappedKey,
      recipient_key_fingerprint: recipient.key_fingerprint,
      recipient_key_version: recipient.key_version,
      expires_at: t + body.expiresInMinutes * 60_000,
      max_downloads: body.maxDownloads,
      decision_id: rec.id,
    });
    req.audit('GRANT_CREATE', 'success', {
      targetType: 'grant',
      targetId: grantId,
      details: { documentId: id, filename: doc.filename, recipient: recipient.username, expiresInMinutes: body.expiresInMinutes, maxDownloads: body.maxDownloads, decisionId: rec.id },
    });
    res.status(201).json({ grantId, decision: rec });
  });

  // ---- open/download: the policy gate in front of every key release
  r.post('/:id/download', requirePerm('doc.download'), sensitive, (req, res) => {
    const started = performance.now();
    const id = idParam(req);
    validate({}, req.body || {});
    const doc = svc.repos.documents.byId(id);
    const grant = doc ? svc.repos.grants.latestFor(id, req.user.id) : null;
    const t = svc.now();
    const decision = evaluateDownload({ user: req.user, document: doc, grant, now: t });
    const label = doc ? doc.filename : 'unknown document';
    const rec = svc.decide(req, { action: 'download', subjectType: 'document', subjectId: id, subjectLabel: label }, decision, started);
    if (decision.decision === 'deny') {
      req.audit('DOWNLOAD_DENY', 'denied', { targetType: 'document', targetId: id, details: { rule: decision.rule, decisionId: rec.id } });
      // No relationship to the document: generic answer that does not confirm it exists.
      if (decision.rule === 'NO_GRANT') throw new AppError('NOT_FOUND');
      throw new AppError('POLICY_DENIED', { message: decision.reason, decision: rec });
    }
    // Consume one download atomically, then release ciphertext + wrapped key.
    const downloadId = randomUUID();
    const result = svc.repos.tx(() => {
      if (!svc.repos.grants.consumeDownload(grant.id)) return null;
      svc.repos.downloads.create({ id: downloadId, grant_id: grant.id, document_id: id, user_id: req.user.id, decision_id: rec.id });
      return { content: svc.repos.documents.content(id), wrappedKey: svc.repos.grants.byId(grant.id).wrapped_key };
    });
    if (!result || !result.content || !result.wrappedKey) {
      req.audit('DOWNLOAD_DENY', 'denied', { targetType: 'document', targetId: id, details: { rule: 'DOWNLOAD_LIMIT_REACHED', race: true } });
      throw new AppError('POLICY_DENIED', { message: 'The grant has no downloads remaining.' });
    }
    const payload = issuePayload(svc.secrets.watermarkKey, { downloadId, grantId: grant.id, userId: req.user.id, documentId: id });
    req.audit('DOWNLOAD_ALLOW', 'success', {
      targetType: 'document',
      targetId: id,
      details: { filename: doc.filename, grantId: grant.id, downloadId, rule: decision.rule, decisionId: rec.id },
    });
    res.json({
      document: docView(doc),
      binding: doc.binding,
      ciphertext: toB64(result.content),
      wrappedKey: result.wrappedKey,
      watermark: { payload, label: wmLabel({ username: req.user.username, issuedAt: t, downloadId }), downloadId },
      decision: rec,
    });
  });

  // ---- the browser reports an AES-GCM authentication failure after a download, so
  // tampering detected client-side is recorded server-side (decision + audit).
  r.post('/:id/integrity-failure', requirePerm('doc.download'), sensitive, (req, res) => {
    const started = performance.now();
    const id = idParam(req);
    const body = validate({ downloadId: v.uuid(), check: v.oneOf(['INTEGRITY_CHECK_FAILED', 'CONTAINER_BAD_MAGIC', 'CONTAINER_UNSUPPORTED_VERSION', 'CONTAINER_BAD_IV_LENGTH', 'CONTAINER_TOO_SHORT']) }, req.body);
    const dl = svc.repos.downloads.byId(body.downloadId);
    if (!dl || dl.user_id !== req.user.id || dl.document_id !== id) throw new AppError('NOT_FOUND');
    const doc = svc.repos.documents.byId(id);
    const decision = {
      decision: 'deny',
      rule: 'INTEGRITY_CHECK_FAILED',
      reason: 'The downloaded ciphertext failed AES-GCM authentication in the browser; nothing was decrypted.',
      evidence: { downloadId: dl.id, grantId: dl.grant_id, failedCheck: body.check, storedCipherSha256: doc?.cipher_sha256 ?? null },
      engine: 'vaultshare-crypto/1.0.0 (client report)',
    };
    const rec = svc.decide(req, { action: 'decrypt', subjectType: 'document', subjectId: id, subjectLabel: doc?.filename ?? 'unknown' }, decision, started);
    req.audit('DOWNLOAD_INTEGRITY_FAILURE', 'error', { targetType: 'document', targetId: id, details: { downloadId: dl.id, check: body.check, decisionId: rec.id } });
    res.status(201).json({ decision: rec });
  });

  return r;
}
