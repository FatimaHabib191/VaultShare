// Shared UI components. Everything is built with createElement / textContent
// (never innerHTML with data), so server- or file-supplied strings cannot inject
// markup, and nothing needs an inline style or script under the strict CSP.
import { ICONS } from './icons.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style') el.style.cssText = v; // CSSOM is allowed by the CSP; style attributes are not
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** Lucide line icon. Decorative by default (aria-hidden); pass label for meaning. */
export function icon(name, { cls = '', label } = {}) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', `icon ${cls}`.trim());
  if (label) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', label);
  } else svg.setAttribute('aria-hidden', 'true');
  for (const [tag, attrs] of ICONS[name] || ICONS.info) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) if (k !== 'key') node.setAttribute(k, v);
    svg.append(node);
  }
  return svg;
}

// ---------------------------------------------------------------- storage (per-viewer conveniences only)
export const prefs = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem(`vs.${key}`);
      return v == null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(`vs.${key}`, JSON.stringify(value));
    } catch {
      /* storage unavailable: preference is simply not remembered */
    }
  },
};

// ---------------------------------------------------------------- formatting
export function formatBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function formatTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function relative(iso) {
  if (!iso) return '';
  const diff = new Date(iso).getTime() - Date.now();
  const abs = Math.abs(diff);
  for (const [u, ms] of [
    ['day', 86_400_000],
    ['hour', 3_600_000],
    ['minute', 60_000],
  ]) {
    if (abs >= ms) {
      const n = Math.round(abs / ms);
      return diff > 0 ? `in ${n} ${u}${n > 1 ? 's' : ''}` : `${n} ${u}${n > 1 ? 's' : ''} ago`;
    }
  }
  return diff > 0 ? 'in under a minute' : 'just now';
}

export const initials = (name = '') => name.replace(/[^a-z0-9]/gi, '').slice(0, 2) || '?';

// ---------------------------------------------------------------- primitives
export function avatar(name, { small = false } = {}) {
  return h('span', { class: `avatar${small ? ' sm' : ''}`, 'aria-hidden': 'true' }, initials(name));
}

/** Coloured chip. kind: success | warning | danger | accent | neutral. Always has text. */
export function chip(text, kind = 'neutral', iconName, extra = '') {
  return h('span', { class: `chip ${kind === 'neutral' ? '' : kind} ${extra}`.trim() }, iconName ? icon(iconName) : null, text);
}

const STATUS = {
  active: ['Active', 'success', 'check-circle'],
  revoked: ['Revoked', 'danger', 'ban'],
  expired: ['Expired', 'warning', 'clock'],
  exhausted: ['No downloads left', 'warning', 'download'],
  key_mismatch: ['Key changed', 'danger', 'key'],
  document_deleted: ['Deleted by owner', 'danger', 'trash'],
  pending: ['Awaiting setup', 'warning', 'clock'],
  disabled: ['Disabled', 'danger', 'ban'],
  allow: ['Allowed', 'success', 'check-circle'],
  deny: ['Denied', 'danger', 'x-circle'],
  success: ['Success', 'success', 'check-circle'],
  denied: ['Denied', 'danger', 'x-circle'],
  error: ['Error', 'danger', 'alert'],
  info: ['Info', 'neutral', 'info'],
};
/** Status chip: colour + icon + word, so status never depends on colour alone. */
export function status(s) {
  const [label, kind, ic] = STATUS[s] || [s, 'neutral', 'info'];
  return chip(label, kind, ic);
}

const SEVERITY = { info: ['Info', 'neutral', 'info'], low: ['Low', 'outline', null], medium: ['Medium', 'warning', 'alert2'], high: ['High', 'danger', 'alert'] };
export function severity(s) {
  if (s === 'info') return h('span', { class: 'muted small', title: 'Severity: Info' }, 'Info');
  const [label, kind, ic] = SEVERITY[s] || [s, 'neutral', null];
  return h('span', { class: `chip ${kind === 'neutral' ? '' : kind}`.trim(), title: `Severity: ${label}` }, ic ? icon(ic) : null, `${label} severity`);
}

export const roleChip = (role) => chip(role, role === 'admin' ? 'accent' : 'outline', role === 'admin' ? 'shield' : role === 'operator' ? 'user' : 'eye', 'role-chip');

const FILE_ICON = { pdf: 'file-pdf', png: 'file-image', jpg: 'file-image', jpeg: 'file-image', csv: 'file-sheet', txt: 'file-text', md: 'file-text' };
export function fileTile(ext, { lg = false } = {}) {
  return h('span', { class: `file-tile${lg ? ' lg' : ''}`, 'aria-hidden': 'true' }, icon(FILE_ICON[ext] || 'file'), h('span', { class: 'ext' }, ext || '?'));
}

export function fingerprint(hex, { copy = false } = {}) {
  if (!hex) return h('span', { class: 'muted' }, 'No key yet');
  const text = (hex.slice(0, 32).match(/.{4}/g) || []).join(' ').toUpperCase();
  return h('span', { class: 'fp', title: hex }, icon('fingerprint', { cls: 'sm' }), text, copy ? copyButton(hex, 'Copy full fingerprint') : null);
}

export function copyButton(text, label = 'Copy') {
  const btn = h('button', { type: 'button', class: 'ghost icon-btn small', 'aria-label': label, 'data-tip': label }, icon('copy', { cls: 'sm' }));
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      await navigator.clipboard.writeText(text);
      toast('Copied to clipboard');
    } catch {
      toast('Copy is not available in this browser. Select the text instead.', { bad: true });
    }
  });
  return btn;
}

/** Disable a button and show a spinner while an async action runs. */
export async function withBusy(btn, fn) {
  btn.disabled = true;
  btn.classList.add('busy');
  btn.setAttribute('aria-busy', 'true');
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
    btn.removeAttribute('aria-busy');
  }
}

// ---------------------------------------------------------------- layout pieces
export function pageHead(title, lead, ...actions) {
  return h(
    'header',
    { class: 'page-head' },
    h('div', {}, h('h1', {}, title), lead ? h('p', { class: 'lead' }, lead) : null),
    actions.filter(Boolean).length ? h('div', { class: 'actions' }, actions) : null
  );
}

/** Card with optional heading, sub-text and header actions. */
export function card({ title, sub, icon: ic, actions, flush = false, cls = '', headingLevel = 'h2', label } = {}, ...children) {
  const head =
    title || actions
      ? h(
          'div',
          { class: 'card-head' },
          h('div', {}, title ? h(headingLevel, {}, ic ? icon(ic, { cls: 'sm' }) : null, title) : null, sub ? h('p', { class: 'sub' }, sub) : null),
          actions ? h('div', { class: 'actions' }, actions) : null
        )
      : null;
  return h('section', { class: `card ${flush ? 'flush' : ''} ${cls}`.trim(), 'aria-label': label || null }, head, children);
}

export function statCard({ icon: ic, value, label, hint, href }) {
  return h(href ? 'a' : 'div', { class: 'stat', href: href || null }, h('span', { class: 'stat-icon' }, icon(ic)), h('div', {}, h('div', { class: 'num' }, String(value)), h('div', { class: 'lbl' }, label), hint ? h('div', { class: 'hint' }, hint) : null));
}

let fieldSeq = 0;
/** Labelled form field. `control` is an <input>/<select>/<textarea> (or a wrapper containing one). */
export function field(label, control, hint) {
  const input = control.matches?.('input,select,textarea') ? control : control.querySelector?.('input,select,textarea');
  if (input && !input.id) input.id = `f${++fieldSeq}`;
  const hintEl = hint ? h('span', { class: 'hint', id: `${input?.id || `f${++fieldSeq}`}-hint` }, hint) : null;
  if (hintEl && input) input.setAttribute('aria-describedby', hintEl.id);
  return h('div', { class: 'field' }, h('label', { for: input?.id || null }, label), control, hintEl);
}

/** Password input with a show/hide toggle. Returns { wrap, input }. */
export function passwordInput(attrs = {}) {
  const input = h('input', { type: 'password', ...attrs });
  const btn = h('button', { type: 'button', class: 'reveal', 'aria-label': 'Show password', 'aria-pressed': 'false' }, icon('eye', { cls: 'sm' }));
  btn.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.setAttribute('aria-pressed', String(show));
    btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    btn.replaceChildren(icon(show ? 'eye-off' : 'eye', { cls: 'sm' }));
  });
  return { wrap: h('div', { class: 'input-wrap' }, input, btn), input };
}

export function searchBox({ placeholder = 'Search', value = '', label = 'Search', oninput } = {}) {
  const input = h('input', { type: 'search', placeholder, value, 'aria-label': label, autocomplete: 'off' });
  if (oninput) input.addEventListener('input', () => oninput(input.value));
  return { wrap: h('div', { class: 'search' }, icon('search', { cls: 'sm' }), input), input };
}

/** Segmented control (e.g. grid/list). options: [{ value, label, icon }] */
export function segmented(options, value, onchange, label) {
  const wrap = h('div', { class: 'segmented', role: 'group', 'aria-label': label });
  const render = (v) =>
    wrap.replaceChildren(
      ...options.map((o) =>
        h(
          'button',
          { type: 'button', 'aria-pressed': String(o.value === v), 'aria-label': o.label, 'data-tip': o.icon ? o.label : null, onclick: () => (render(o.value), onchange(o.value)) },
          o.icon ? icon(o.icon, { cls: 'sm' }) : null,
          o.icon ? null : o.label
        )
      )
    );
  render(value);
  return wrap;
}

export function emptyState({ icon: ic = 'inbox', title, body, action } = {}) {
  return h('div', { class: 'empty' }, h('div', { class: 'e-icon' }, icon(ic)), h('h3', {}, title), body ? h('p', {}, body) : null, action ? h('div', { class: 'actions' }, action) : null);
}
// kept for older call sites
export const empty = (title, body, action) => emptyState({ title, body, action });

export function alertBox(kind, title, body, iconName) {
  const ic = iconName || { danger: 'alert2', success: 'check-circle', warning: 'alert', info: 'info' }[kind];
  return h('div', { class: `alert ${kind}`, role: kind === 'danger' ? 'alert' : 'status' }, icon(ic), h('div', {}, title ? h('strong', {}, title) : null, body));
}

export function errorBox(err) {
  const details = err?.details?.length ? h('ul', {}, err.details.map((d) => h('li', {}, `${d.field} ${d.message}`))) : null;
  return h(
    'div',
    { class: 'alert danger', role: 'alert' },
    icon('alert2'),
    h('div', {}, h('strong', {}, err?.message || 'The request failed.'), details, err?.code ? h('div', { class: 'code' }, `${err.code}${err.requestId ? ` · request ${err.requestId.slice(0, 8)}` : ''}`) : null)
  );
}

export function skeletonPage(kind = 'table') {
  const sk = (cls) => h('span', { class: `skeleton ${cls}` });
  const body =
    kind === 'cards'
      ? h('div', { class: 'sk-grid' }, sk('sk-card'), sk('sk-card'), sk('sk-card'), sk('sk-card'))
      : h('div', { class: 'sk-page' }, sk('sk-row'), sk('sk-row'), sk('sk-row'), sk('sk-row'));
  return h('div', { class: 'sk-page', 'aria-busy': 'true', 'aria-label': 'Loading' }, sk('sk-title'), sk('sk-line'), body);
}

// ---------------------------------------------------------------- decision card
const EVIDENCE_LABELS = {
  grantId: 'Grant', isOwnerGrant: 'Owner grant', expiresAt: 'Expires', evaluatedAt: 'Evaluated at', downloadsUsed: 'Downloads used before this',
  downloadLimit: 'Download limit', grantKeyVersion: 'Key version on grant', currentKeyVersion: 'Current key version', revokedAt: 'Revoked at',
  requestedMinutes: 'Requested (minutes)', maxMinutes: 'Allowed maximum (minutes)', requestedDownloads: 'Requested downloads', maxDownloads: 'Allowed maximum downloads',
  declaredSize: 'Declared size (bytes)', ciphertextBytes: 'Ciphertext (bytes)', expectedBytes: 'Expected (bytes)', maxBytes: 'Size limit (bytes)', sizeBytes: 'Size (bytes)',
  mimeType: 'Declared type', extension: 'Extension', allowed: 'Allowed types', check: 'Failed check', failedCheck: 'Failed check', containerVersion: 'Container version',
  checked: 'Events checked', atSeq: 'Broken at event', head: 'Chain head', detectedContent: 'Detected content', expectedContent: 'Expected content', firstBytes: 'First bytes',
  recipient: 'Recipient', recipientRole: 'Recipient role', document: 'Document', documentOwner: 'Document owner', downloadId: 'Download', downloadedAt: 'Downloaded at',
};
const evLabel = (k) => EVIDENCE_LABELS[k] || k.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase());

/** Explainable decision: verdict, rule, severity, reason, next step, evidence, provenance. */
export function decisionCard(decision, { subject, title, openEvidence = false } = {}) {
  if (!decision) return null;
  const kind = decision.decision === 'allow' ? 'allow' : decision.decision === 'deny' ? 'deny' : 'info';
  const verdict = title || (kind === 'allow' ? 'Allowed' : kind === 'deny' ? 'Denied' : 'Recorded');
  const ev = Object.entries(decision.evidence || {}).filter(([, v]) => v !== null && v !== undefined && v !== '');
  return h(
    'section',
    { class: `decision ${kind} enter`, 'aria-label': `Decision: ${verdict}, rule ${decision.rule}` },
    h(
      'div',
      { class: 'decision-head' },
      h('span', { class: 'd-icon' }, icon(kind === 'allow' ? 'check-circle' : kind === 'deny' ? 'x-circle' : 'info')),
      h(
        'div',
        { class: 'd-main' },
        h('div', { class: 'd-title' }, h('span', { class: 'verdict' }, verdict), chip(decision.rule, 'outline', null, 'mono'), decision.severity && decision.severity !== 'info' ? severity(decision.severity) : null),
        h('p', { class: 'reason' }, decision.reason),
        subject ? h('p', { class: 'subject' }, subject) : null
      )
    ),
    decision.recommendedAction || ev.length
      ? h(
          'div',
          { class: 'decision-body' },
          decision.recommendedAction ? h('div', { class: 'next-step' }, icon('chevron-right'), h('div', {}, h('strong', {}, 'What to do: '), decision.recommendedAction)) : null,
          ev.length
            ? h(
                'details',
                { open: openEvidence || null },
                h('summary', {}, icon('chevron-right'), `Evidence (${ev.length})`),
                h('dl', { class: 'dl' }, ev.map(([k, v]) => [h('dt', {}, evLabel(k)), h('dd', { class: typeof v === 'string' && /^[0-9a-f-]{16,}$/.test(v) ? 'mono' : null }, typeof v === 'object' ? JSON.stringify(v) : String(v))]))
              )
            : null
        )
      : null,
    h(
      'div',
      { class: 'decision-foot' },
      decision.engine ? h('span', {}, decision.engine) : null,
      decision.configVersion != null ? h('span', {}, `settings v${decision.configVersion}`) : null,
      decision.latencyMs != null ? h('span', {}, `${Number(decision.latencyMs).toFixed(2)} ms`) : null,
      decision.id ? h('span', { title: decision.id }, `#${decision.id.slice(0, 8)}`) : null
    )
  );
}
export const slip = decisionCard;

// ---------------------------------------------------------------- overlays
function openDialog(content, { drawer = false, labelledBy, onClose } = {}) {
  const dlg = h('dialog', { class: drawer ? 'drawer-dialog' : null, 'aria-labelledby': labelledBy || null }, content);
  const close = (v) => {
    if (!dlg.open) return;
    dlg.close();
    dlg.remove();
    onClose?.(v);
  };
  dlg.addEventListener('cancel', (e) => {
    e.preventDefault();
    close(false);
  });
  dlg.addEventListener('click', (e) => {
    if (e.target === dlg) close(false); // click on the backdrop
  });
  document.body.append(dlg);
  dlg.showModal();
  return { dlg, close };
}

let dlgSeq = 0;
/** Confirmation for high-impact actions. Resolves true / false. */
export function confirmDialog({ title, body, confirmLabel, danger = false, icon: ic }) {
  return new Promise((resolve) => {
    const id = `dlg-${++dlgSeq}`;
    const ok = h('button', { type: 'button', class: danger ? 'danger solid' : 'primary' }, confirmLabel);
    const cancel = h('button', { type: 'button' }, 'Cancel');
    const { close } = openDialog(
      h(
        'div',
        { class: 'modal' },
        h('div', { class: 'modal-body' }, h('span', { class: `m-icon${danger ? ' danger' : ''}` }, icon(ic || (danger ? 'alert' : 'info'))), h('div', { class: 'm-content' }, h('h2', { id }, title), body ? h('p', {}, body) : null)),
        h('div', { class: 'modal-foot' }, cancel, ok)
      ),
      { labelledBy: id, onClose: resolve }
    );
    ok.addEventListener('click', () => close(true));
    cancel.addEventListener('click', () => close(false));
    cancel.focus();
  });
}

/** Generic modal with arbitrary content; returns { close }. */
export function modal({ title, icon: ic, content, footer, wide = false }) {
  const id = `dlg-${++dlgSeq}`;
  return openDialog(
    h(
      'div',
      { class: `modal${wide ? ' wide' : ''}` },
      h('div', { class: 'modal-body' }, ic ? h('span', { class: 'm-icon' }, icon(ic)) : null, h('div', { class: 'm-content' }, h('h2', { id }, title), content)),
      footer ? h('div', { class: 'modal-foot' }, footer) : null
    ),
    { labelledBy: id }
  );
}

/** Side drawer for details. */
export function drawer({ title, content }) {
  const id = `dlg-${++dlgSeq}`;
  const closeBtn = h('button', { type: 'button', class: 'ghost icon-btn', 'aria-label': 'Close' }, icon('x'));
  const ref = openDialog(h('div', { class: 'drawer' }, h('div', { class: 'drawer-head' }, h('h2', { id }, title), closeBtn), h('div', { class: 'drawer-body' }, content)), { drawer: true, labelledBy: id });
  closeBtn.addEventListener('click', () => ref.close(false));
  closeBtn.focus();
  return ref;
}

/** Dropdown menu anchored to a trigger button. items: [{ label, icon, href, onclick, danger }] or Nodes. */
export function dropdown(trigger, items, { up = false, head } = {}) {
  const menu = h('div', { class: `menu${up ? ' up' : ''}`, role: 'menu' });
  if (head) menu.append(h('div', { class: 'm-head' }, head));
  for (const it of items) {
    if (it instanceof Node) {
      menu.append(it);
      continue;
    }
    const el = h(it.href ? 'a' : 'button', { role: 'menuitem', href: it.href || null, type: it.href ? null : 'button', class: it.danger ? 'm-danger' : null }, it.icon ? icon(it.icon, { cls: 'sm' }) : null, it.label);
    el.addEventListener('click', (e) => {
      setOpen(false);
      it.onclick?.(e);
    });
    menu.append(el);
  }
  trigger.setAttribute('aria-haspopup', 'menu');
  trigger.setAttribute('aria-expanded', 'false');
  const wrap = h('div', { class: 'menu-wrap' }, trigger, menu);
  function setOpen(open) {
    menu.classList.toggle('open', open);
    trigger.setAttribute('aria-expanded', String(open));
    if (open) menu.querySelector('[role=menuitem]')?.focus();
  }
  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    setOpen(!menu.classList.contains('open'));
  });
  document.addEventListener('click', (e) => {
    if (!wrap.contains(e.target)) setOpen(false);
  });
  wrap.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      setOpen(false);
      trigger.focus();
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const list = [...menu.querySelectorAll('[role=menuitem]')];
      if (!list.length) return;
      e.preventDefault();
      const i = list.indexOf(document.activeElement);
      list[(i + (e.key === 'ArrowDown' ? 1 : -1) + list.length) % list.length].focus();
    }
  });
  return wrap;
}

export function toast(message, { bad = false, ms = 4500 } = {}) {
  const host = document.getElementById('toasts');
  if (!host) return;
  const close = h('button', { type: 'button', 'aria-label': 'Dismiss' }, icon('x', { cls: 'sm' }));
  const t = h('div', { class: `toast${bad ? ' bad' : ''}`, role: bad ? 'alert' : 'status' }, icon(bad ? 'alert2' : 'check-circle'), h('div', { class: 'msg' }, message), close);
  const remove = () => {
    t.classList.add('leaving');
    setTimeout(() => t.remove(), 160);
  };
  close.addEventListener('click', remove);
  host.append(t);
  setTimeout(remove, ms);
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
