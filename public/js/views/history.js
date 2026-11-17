import { h, icon, pageHead, card, status, severity, chip, avatar, roleChip, emptyState, formatTime, relative, decisionCard, errorBox, alertBox, field, passwordInput, toast, fingerprint, downloadBlob, drawer, withBusy, searchBox } from '../ui.js';
import { get, fetchFile } from '../api.js';
import { state, changePassword } from '../vault.js';

const ACTION_LABEL = { download: 'Open file', share: 'Share', upload: 'Upload check', upload_content: 'Upload ciphertext', decrypt: 'Integrity check', audit_verify: 'Audit verification', watermark_trace: 'Leak trace' };

export async function renderHistory(main, { adminScope = false } = {}) {
  const scopeAll = state.user.role === 'admin' && adminScope;
  const decision = h('select', { 'aria-label': 'Filter by result' }, h('option', { value: '' }, 'All results'), h('option', { value: 'allow' }, 'Allowed'), h('option', { value: 'deny' }, 'Denied'));
  const sev = h('select', { 'aria-label': 'Filter by severity' }, h('option', { value: '' }, 'All severities'), ['high', 'medium', 'low', 'info'].map((v) => h('option', { value: v }, `${v[0].toUpperCase()}${v.slice(1)} severity`)));
  const action = h('select', { 'aria-label': 'Filter by action' }, h('option', { value: '' }, 'All actions'), Object.entries(ACTION_LABEL).map(([v, l]) => h('option', { value: v }, l)));
  const actor = searchBox({ placeholder: 'Filter by username', label: 'Filter by username' });
  const body = h('div', { 'aria-live': 'polite' });
  const count = h('span', { class: 'count' });

  const qs = () => {
    const p = new URLSearchParams({ limit: '300' });
    if (scopeAll) p.set('scope', 'all');
    if (decision.value) p.set('decision', decision.value);
    if (action.value) p.set('action', action.value);
    if (sev.value) p.set('severity', sev.value);
    if (scopeAll && actor.input.value.trim()) p.set('actor', actor.input.value.trim().toLowerCase());
    return p.toString();
  };

  async function load() {
    body.replaceChildren(h('span', { class: 'skeleton sk-row' }), h('span', { class: 'skeleton sk-row', style: 'margin-top:8px' }));
    try {
      const { decisions } = await get(`/api/decisions?${qs()}`);
      count.textContent = `${decisions.length} decision${decisions.length === 1 ? '' : 's'}`;
      body.replaceChildren(
        decisions.length
          ? h(
              'div',
              { class: 'card flush' },
              h(
                'div',
                { class: 'table-wrap' },
                h(
                  'table',
                  { class: 'stack-sm' },
                  h('thead', {}, h('tr', {}, h('th', {}, 'Result'), h('th', {}, 'What'), scopeAll ? h('th', {}, 'Who') : null, h('th', {}, 'Rule'), h('th', {}, 'Severity'), h('th', {}, 'When'), h('th', {}, h('span', { class: 'sr-only' }, 'Details')))),
                  h(
                    'tbody',
                    {},
                    decisions.map((d) => {
                      const open = h('button', { type: 'button', class: 'small', 'aria-label': `Details for ${ACTION_LABEL[d.action] || d.action} ${d.subject || ''}` }, 'Details');
                      open.addEventListener('click', (e) => {
                        e.stopPropagation();
                        show(d);
                      });
                      return h(
                        'tr',
                        { class: 'clickable', onclick: () => show(d) },
                        h('td', {}, status(d.decision)),
                        h('td', { 'data-label': 'What' }, h('div', { class: 'cell-main' }, h('div', { class: 't' }, h('strong', { title: d.subject || '' }, d.subject || '—'), h('div', { class: 'sub' }, ACTION_LABEL[d.action] || d.action)))),
                        scopeAll ? h('td', { 'data-label': 'Who' }, d.actor || '—') : null,
                        h('td', { 'data-label': 'Rule' }, chip(d.rule, 'outline', null, 'mono')),
                        h('td', { 'data-label': 'Severity' }, severity(d.severity)),
                        h('td', { 'data-label': 'When', title: formatTime(d.ts) }, relative(d.ts)),
                        h('td', { class: 'actions-cell' }, h('div', { class: 'actions' }, open))
                      );
                    })
                  )
                )
              )
            )
          : card({}, emptyState({ icon: 'decisions', title: 'No decisions match', body: 'Decisions appear here when files are uploaded, shared or opened. Try clearing the filters.' }))
      );
    } catch (e) {
      body.replaceChildren(errorBox(e));
    }
  }

  function show(d) {
    drawer({
      title: ACTION_LABEL[d.action] || d.action,
      content: [
        decisionCard(d, { subject: `${d.subject || ''} · ${formatTime(d.ts)}${d.actor ? ` · ${d.actor}` : ''}`, openEvidence: true }),
        h('p', { class: 'hint', style: 'margin-top:12px' }, 'The rule, evidence, engine version and settings version are stored with every decision so the result can be reproduced.'),
      ],
    });
  }

  async function exportAs(format, btn) {
    await withBusy(btn, async () => {
      try {
        const { blob, name } = await fetchFile(`/api/reports/export?format=${format}&${qs()}`);
        downloadBlob(blob, name);
        toast(`Exported ${name}`);
      } catch (e) {
        toast(e.message, { bad: true });
      }
    });
  }
  const jsonBtn = h('button', { type: 'button' }, icon('export', { cls: 'sm' }), 'Export report');
  jsonBtn.addEventListener('click', () => exportAs('json', jsonBtn));
  const csvBtn = h('button', { type: 'button' }, icon('download', { cls: 'sm' }), 'Export CSV');
  csvBtn.addEventListener('click', () => exportAs('csv', csvBtn));

  for (const el of [decision, sev, action]) el.addEventListener('change', load);
  let t;
  actor.input.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(load, 300);
  });

  main.replaceChildren(
    pageHead(
      scopeAll ? 'All decisions' : 'My decisions',
      scopeAll ? 'Every policy decision across all users, with the rule, evidence and settings version that produced it.' : 'Every allow or deny decision about your requests. Open one to see the rule and evidence behind it. Exports contain no keys or file contents.',
      jsonBtn,
      csvBtn
    ),
    h('div', { class: 'toolbar' }, scopeAll ? actor.wrap : null, decision, sev, action, count),
    body
  );
  load();
}

export function renderAccount(main) {
  const cur = passwordInput({ autocomplete: 'current-password' });
  const next = passwordInput({ autocomplete: 'new-password', minlength: '10' });
  const next2 = passwordInput({ autocomplete: 'new-password' });
  const out = h('div', { 'aria-live': 'polite' });
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Change password');
  const form = h(
    'form',
    {
      onsubmit: async (e) => {
        e.preventDefault();
        out.replaceChildren();
        if (!cur.input.value) return out.append(errorBox({ message: 'Enter your current password.' }));
        if (next.input.value.length < 10) return out.append(errorBox({ message: 'The new password must be at least 10 characters.' }));
        if (next.input.value !== next2.input.value) return out.append(errorBox({ message: 'The new passwords do not match.' }));
        await withBusy(btn, async () => {
          try {
            await changePassword(cur.input.value, next.input.value);
            cur.input.value = next.input.value = next2.input.value = '';
            out.append(alertBox('success', 'Password changed', 'Your key is re-locked with the new password. Other sessions were signed out.'));
          } catch (ex) {
            out.append(errorBox(ex));
          }
        });
      },
    },
    out,
    field('Current password', cur.wrap),
    h('div', { class: 'row' }, field('New password', next.wrap, 'At least 10 characters.'), field('Confirm new password', next2.wrap)),
    btn
  );

  main.replaceChildren(
    pageHead('Account', 'Your identity, your encryption key, and your password.'),
    h(
      'div',
      { class: 'split' },
      h(
        'div',
        {},
        card(
          { title: 'Profile', icon: 'user' },
          h('div', { class: 'cell-main', style: 'margin-bottom:16px' }, avatar(state.user.username), h('div', { class: 't' }, h('strong', {}, state.user.username), h('div', { class: 'sub' }, 'Signed in'))),
          h('dl', { class: 'dl' }, h('dt', {}, 'Role'), h('dd', {}, roleChip(state.user.role)), h('dt', {}, 'Status'), h('dd', {}, status(state.user.status || 'active')))
        ),
        card({ title: 'Change password', icon: 'lock', sub: 'Your private key is re-locked with the new password in this browser. Other sessions are signed out.' }, form)
      ),
      h(
        'div',
        {},
        card(
          { title: 'Your public key', icon: 'fingerprint', sub: 'People sharing with you can compare this fingerprint with what their screen shows. If it ever differs, do not trust the share.' },
          fingerprint(state.user.keyFingerprint, { copy: true }),
          h('dl', { class: 'dl', style: 'margin-top:16px' }, h('dt', {}, 'Key version'), h('dd', {}, `v${state.user.keyVersion}`), h('dt', {}, 'Algorithm'), h('dd', {}, 'RSA-OAEP 2048, SHA-256'), h('dt', {}, 'Private key'), h('dd', {}, 'Stored only in encrypted form; unlocked in this tab'))
        ),
        alertBox('warning', 'There is no password recovery', 'If you forget your password an administrator can issue a new key, but files shared with your current key would need to be shared again.')
      )
    )
  );
}
