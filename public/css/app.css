import {
  h, icon, pageHead, card, statCard, chip, status, severity, roleChip, avatar, emptyState, formatTime, relative, decisionCard, errorBox, alertBox,
  field, toast, confirmDialog, modal, downloadBlob, searchBox, withBusy, copyButton,
} from '../ui.js';
import { get, post, put, fetchFile } from '../api.js';
import { state } from '../vault.js';
import { extractWatermarks } from '../files.js';

// ================================================================ overview
export async function renderOverview(main) {
  const [o, review] = await Promise.all([get('/api/admin/overview'), get('/api/decisions?scope=all&severity=high&limit=6')]);
  const allow = o.decisionStats.filter((s) => s.decision === 'allow').reduce((a, s) => a + s.n, 0);
  const deny = o.decisionStats.filter((s) => s.decision === 'deny').reduce((a, s) => a + s.n, 0);
  const perms = Object.keys(o.permissions);

  const reviewCard = card(
    { title: 'Needs review', icon: 'shield-alert', sub: 'Latest high-severity decisions across all users', actions: h('a', { class: 'btn small', href: '#/admin/decisions' }, 'All decisions') },
    review.decisions.length
      ? h(
          'ul',
          { class: 'list' },
          review.decisions.map((d) =>
            h(
              'li',
              {},
              h('span', { class: `dot-icon ${d.decision === 'allow' ? 'warning' : 'danger'}` }, icon(d.decision === 'allow' ? 'alert' : 'x', { label: d.decision === 'allow' ? 'Allowed, high severity' : 'Denied' })),
              h('div', { class: 't' }, h('strong', {}, `${d.rule} · ${d.subject || '—'}`), h('div', { class: 'sub' }, `${d.actor || 'unknown'} · ${relative(d.ts)}`))
            )
          )
        )
      : emptyState({ icon: 'shield', title: 'Nothing needs review', body: 'High-severity results such as tampered files, disguised uploads or traced leaks appear here.' })
  );

  const rules = card(
    { title: 'Decisions by rule', flush: true },
    o.decisionStats.length
      ? h(
          'div',
          { class: 'table-wrap', style: 'margin-top:4px' },
          h(
            'table',
            { class: 'stack-sm' },
            h('thead', {}, h('tr', {}, h('th', {}, 'Rule'), h('th', {}, 'Action'), h('th', {}, 'Result'), h('th', {}, 'Severity'), h('th', { class: 'num' }, 'Count'), h('th', { class: 'num' }, 'Avg ms'))),
            h(
              'tbody',
              {},
              o.decisionStats.map((s) =>
                h('tr', {}, h('td', {}, chip(s.rule, 'outline', null, 'mono')), h('td', { 'data-label': 'Action' }, s.action), h('td', { 'data-label': 'Result' }, status(s.decision)), h('td', { 'data-label': 'Severity' }, severity(s.severity)), h('td', { class: 'num', 'data-label': 'Count' }, String(s.n)), h('td', { class: 'num', 'data-label': 'Average latency' }, s.avg_ms.toFixed(2)))
              )
            )
          )
        )
      : h('div', { style: 'padding:0 24px 24px' }, emptyState({ icon: 'decisions', title: 'No decisions yet', body: 'They appear as people upload, share and open files.' }))
  );

  const versions = card(
    { title: 'System', icon: 'server' },
    h('dl', { class: 'dl' }, h('dt', {}, 'Policy engine'), h('dd', { class: 'mono' }, o.versions.engine), h('dt', {}, 'Crypto core'), h('dd', { class: 'mono' }, o.versions.crypto), h('dt', {}, 'Settings'), h('dd', {}, h('a', { href: '#/admin/settings' }, `Version ${o.versions.settings}`)))
  );

  const matrix = card(
    { title: 'Permissions by role', icon: 'key', sub: 'Enforced by the server on every request. Administrators hold no document keys.', flush: true },
    h(
      'div',
      { class: 'table-wrap', style: 'margin-top:4px' },
      h(
        'table',
        { class: 'matrix' },
        h('thead', {}, h('tr', {}, h('th', {}, 'Permission'), h('th', {}, 'Admin'), h('th', {}, 'Operator'), h('th', {}, 'Viewer'))),
        h('tbody', {}, perms.map((a) => h('tr', {}, h('td', {}, a), ['admin', 'operator', 'viewer'].map((r) => h('td', {}, o.permissions[a][r] ? chip('Yes', 'success', 'check') : h('span', { class: 'muted', 'aria-label': 'Not allowed' }, '—'))))))
      )
    )
  );

  main.replaceChildren(
    pageHead('Overview', 'System health at a glance. Administrators manage people, policy and evidence but cannot read documents.', h('a', { class: 'btn primary', href: '#/admin/audit' }, icon('audit', { cls: 'sm' }), 'Open audit trail')),
    h(
      'div',
      { class: 'stats' },
      statCard({ icon: 'users', value: o.users.total, label: 'People', hint: `${o.users.byRole.operator} operators · ${o.users.byRole.viewer} viewers · ${o.users.pending} awaiting setup`, href: '#/admin/users' }),
      statCard({ icon: 'check-circle', value: allow, label: 'Decisions allowed', href: '#/admin/decisions' }),
      statCard({ icon: 'x-circle', value: deny, label: 'Decisions denied', href: '#/admin/decisions' }),
      statCard({ icon: 'audit', value: o.auditEvents, label: 'Audit events', hint: 'Hash-chained', href: '#/admin/audit' })
    ),
    h('div', { class: 'split' }, h('div', {}, reviewCard), h('div', {}, versions)),
    h('div', { class: 'section' }, rules),
    h('div', { class: 'section' }, matrix)
  );
}

// ================================================================ people
export async function renderUsers(main, { query } = {}) {
  const { users } = await get('/api/admin/users');
  const ui = { q: query?.get('q') || '', role: '' };
  const tableHost = h('div', {});
  const count = h('span', { class: 'count' });
  const search = searchBox({ placeholder: 'Search people', value: ui.q, label: 'Search people', oninput: (v) => ((ui.q = v), draw()) });
  const roleSel = h('select', { 'aria-label': 'Filter by role' }, h('option', { value: '' }, 'All roles'), ['admin', 'operator', 'viewer'].map((r) => h('option', { value: r }, `${r[0].toUpperCase()}${r.slice(1)}s`)));
  roleSel.addEventListener('change', () => ((ui.role = roleSel.value), draw()));
  window.addEventListener('vs:search', function onSearch(e) {
    if (!document.body.contains(tableHost)) return window.removeEventListener('vs:search', onSearch);
    ui.q = e.detail;
    search.input.value = e.detail;
    draw();
  });
  const reload = () => renderUsers(main, { query });

  function showCode(title, username, code) {
    const done = h('button', { type: 'button', class: 'primary' }, 'Done');
    const ref = modal({
      title,
      icon: 'key',
      content: [
        h('p', {}, `Give this one-time code to ${username} through a separate channel, such as in person or by phone. It is shown only once and expires.`),
        h('div', { class: 'actions', style: 'margin-top:16px' }, h('span', { class: 'code-once' }, code), copyButton(code, 'Copy code')),
        h('p', { class: 'hint', style: 'margin-top:12px' }, `${username} chooses Set up your account on the sign-in page and enters this code.`),
      ],
      footer: done,
    });
    done.addEventListener('click', () => ref.close());
  }

  function addPerson() {
    const uname = h('input', { autocapitalize: 'none', spellcheck: 'false', placeholder: 'e.g. sara', required: true });
    const role = h('select', {}, h('option', { value: 'operator' }, 'Operator — uploads and shares'), h('option', { value: 'viewer' }, 'Viewer — opens shared files only'), h('option', { value: 'admin' }, 'Administrator — manages the system'));
    const err = h('div', { 'aria-live': 'assertive' });
    const create = h('button', { type: 'submit', class: 'primary', form: 'add-person' }, 'Create and get code');
    const cancel = h('button', { type: 'button' }, 'Cancel');
    const form = h(
      'form',
      {
        id: 'add-person',
        style: 'margin-top:16px',
        onsubmit: async (e) => {
          e.preventDefault();
          err.replaceChildren();
          await withBusy(create, async () => {
            try {
              const r = await post('/api/admin/users', { username: uname.value.trim().toLowerCase(), role: role.value });
              ref.close();
              await reload();
              showCode(`Enrollment code for ${r.user.username}`, r.user.username, r.enrollmentCode);
            } catch (ex) {
              err.append(errorBox(ex));
            }
          });
        },
      },
      err,
      field('Username', uname, '3–32 lowercase letters, digits, dot, dash or underscore.'),
      field('Role', role)
    );
    const ref = modal({ title: 'Add a person', icon: 'user-plus', content: [h('p', {}, 'They finish setup themselves with a one-time code, which creates their key pair in their own browser.'), form], footer: [cancel, create] });
    cancel.addEventListener('click', () => ref.close());
    uname.focus();
  }

  async function act(u, kind, btn) {
    const conf = {
      reset: { title: u.status === 'pending' ? `Issue a new code for ${u.username}?` : `Issue a new key for ${u.username}?`, body: u.status === 'pending' ? 'The previous code stops working.' : 'Their current key stops working. Files shared with their old key must be shared again, and files they own become unrecoverable. Use this only for a lost password or a compromised key.', label: u.status === 'pending' ? 'Issue new code' : 'Reset key', danger: u.status !== 'pending', icon: 'key' },
      disable: { title: `Disable ${u.username}?`, body: 'They are signed out immediately and cannot sign in until re-enabled.', label: 'Disable account', danger: true, icon: 'ban' },
      enable: { title: `Enable ${u.username}?`, body: 'They will be able to sign in again.', label: 'Enable account', icon: 'user-check' },
    }[kind];
    if (!(await confirmDialog({ title: conf.title, body: conf.body, confirmLabel: conf.label, danger: conf.danger, icon: conf.icon }))) return;
    await withBusy(btn, async () => {
      try {
        if (kind === 'reset') {
          const r = await post(`/api/admin/users/${u.id}/reset`, { confirm: true });
          await reload();
          showCode(`New enrollment code for ${u.username}`, u.username, r.enrollmentCode);
        } else {
          await post(`/api/admin/users/${u.id}/status`, { status: kind === 'disable' ? 'disabled' : 'active', confirm: true });
          toast(`${u.username} ${kind === 'disable' ? 'disabled' : 'enabled'}`);
          reload();
        }
      } catch (e) {
        toast(e.message, { bad: true });
      }
    });
  }

  async function changeRole(u, sel) {
    const to = sel.value;
    if (to === u.role) return;
    const ok = await confirmDialog({ title: `Make ${u.username} ${to === 'admin' ? 'an administrator' : `a ${to}`}?`, body: 'They are signed out now, and the new permissions apply when they next sign in.', confirmLabel: 'Change role', icon: 'users' });
    if (!ok) return (sel.value = u.role);
    try {
      await post(`/api/admin/users/${u.id}/role`, { role: to, confirm: true });
      toast(`${u.username} is now ${to}`);
      reload();
    } catch (e) {
      sel.value = u.role;
      toast(e.message, { bad: true });
    }
  }

  function draw() {
    const q = ui.q.trim().toLowerCase();
    const list = users.filter((u) => (!ui.role || u.role === ui.role) && (!q || u.username.includes(q)));
    count.textContent = `${list.length} of ${users.length} people`;
    if (!list.length) {
      tableHost.replaceChildren(card({}, emptyState({ icon: 'search', title: 'No one matches', body: 'Try a different name or role.' })));
      return;
    }
    tableHost.replaceChildren(
      h(
        'div',
        { class: 'card flush' },
        h(
          'div',
          { class: 'table-wrap' },
          h(
            'table',
            { class: 'stack-sm' },
            h('thead', {}, h('tr', {}, h('th', {}, 'Person'), h('th', {}, 'Role'), h('th', {}, 'Status'), h('th', {}, 'Key'), h('th', {}, 'Last sign-in'), h('th', {}, h('span', { class: 'sr-only' }, 'Actions')))),
            h(
              'tbody',
              {},
              list.map((u) => {
                const self = u.id === state.user.id;
                const sel = h('select', { 'aria-label': `Role for ${u.username}`, disabled: self, style: 'min-height:34px;width:auto;min-width:130px' }, ['admin', 'operator', 'viewer'].map((r) => h('option', { value: r }, `${r[0].toUpperCase()}${r.slice(1)}`)));
                sel.value = u.role;
                sel.addEventListener('change', () => changeRole(u, sel));
                const resetBtn = self ? null : h('button', { type: 'button', class: 'small' }, icon('key', { cls: 'sm' }), u.status === 'pending' ? 'New code' : 'Reset key');
                resetBtn?.addEventListener('click', () => act(u, 'reset', resetBtn));
                const toggleBtn = self || u.status === 'pending' ? null : u.status === 'active' ? h('button', { type: 'button', class: 'small danger' }, 'Disable') : h('button', { type: 'button', class: 'small' }, 'Enable');
                toggleBtn?.addEventListener('click', () => act(u, u.status === 'active' ? 'disable' : 'enable', toggleBtn));
                return h(
                  'tr',
                  {},
                  h('td', {}, h('div', { class: 'cell-main' }, avatar(u.username, { small: true }), h('div', { class: 't' }, h('strong', {}, u.username, self ? h('span', { class: 'muted' }, ' (you)') : null), h('div', { class: 'sub' }, `Joined ${formatTime(u.createdAt)}`)))),
                  h('td', { 'data-label': 'Role' }, self ? roleChip(u.role) : sel),
                  h('td', { 'data-label': 'Status' }, status(u.status)),
                  h('td', { 'data-label': 'Key' }, u.keyFingerprint ? h('span', { class: 'mono-sm' }, `v${u.keyVersion} · ${u.keyFingerprint.slice(0, 12)}`) : h('span', { class: 'muted small' }, `Code expires ${relative(u.enrollmentExpiresAt)}`)),
                  h('td', { 'data-label': 'Last sign-in' }, u.lastLoginAt ? relative(u.lastLoginAt) : 'Never'),
                  h('td', { class: 'actions-cell' }, h('div', { class: 'actions' }, resetBtn, toggleBtn))
                );
              })
            )
          )
        )
      )
    );
  }

  const addBtn = h('button', { type: 'button', class: 'primary' }, icon('user-plus', { cls: 'sm' }), 'Add person');
  addBtn.addEventListener('click', addPerson);
  main.replaceChildren(
    pageHead('People', 'Create accounts and manage roles. New people finish setup themselves with a one-time code, which generates their key pair in their own browser.', addBtn),
    h('div', { class: 'toolbar' }, search.wrap, roleSel, count),
    tableHost
  );
  draw();
}

// ================================================================ settings
const SETTING_GROUPS = [
  ['Uploads', 'What people can upload. Checked on the server for every file.', ['max_file_size_mb', 'allowed_extensions']],
  ['Sharing', 'Limits that apply when someone shares a file.', ['max_grant_ttl_hours', 'default_grant_ttl_hours', 'max_downloads_cap']],
  ['Sessions and sign-in', 'How long sessions last and how hard sign-in is throttled.', ['session_idle_minutes', 'session_absolute_hours', 'login_attempts_per_15min', 'sensitive_actions_per_min']],
  ['Keys and enrollment', 'Applies to new enrollments and new codes.', ['kdf_iterations', 'enrollment_code_hours']],
];

export async function renderSettings(main) {
  const s = await get('/api/admin/settings');
  const inputs = {};
  const out = h('div', { 'aria-live': 'polite' });
  const changedLabel = h('span', { class: 'muted small' }, 'No unsaved changes');

  const control = (key) => {
    const def = s.schema[key];
    if (def.type === 'list') {
      inputs[key] = def.values.map((v) => h('input', { type: 'checkbox', value: v, checked: s.values[key].includes(v) }));
      return h('fieldset', {}, h('legend', { class: 'label', style: 'margin-bottom:8px' }, def.label), h('div', { class: 'checks' }, inputs[key].map((cb) => h('label', { class: 'check-pill' }, cb, `.${cb.value}`))));
    }
    inputs[key] = h('input', { type: 'number', min: String(def.min), max: String(def.max), step: '1', value: String(s.values[key]) });
    return field(def.label, inputs[key], `${def.min.toLocaleString()}–${def.max.toLocaleString()} · default ${Array.isArray(def.default) ? '' : def.default.toLocaleString()}`);
  };

  const current = () => {
    const changes = {};
    for (const [key, def] of Object.entries(s.schema)) {
      const val = def.type === 'list' ? inputs[key].filter((c) => c.checked).map((c) => c.value) : Number(inputs[key].value);
      if (JSON.stringify(val) !== JSON.stringify(s.values[key])) changes[key] = val;
    }
    return changes;
  };

  const sections = SETTING_GROUPS.map(([title, desc, keys]) => h('div', { class: 'settings-section' }, h('div', { class: 's-desc' }, h('h3', {}, title), h('p', {}, desc)), h('div', { class: 's-fields' }, keys.filter((k) => s.schema[k]).map(control))));
  const reason = h('input', { placeholder: 'Why are you changing this?' });
  const apply = h('button', { type: 'submit', class: 'primary' }, 'Review and apply');
  const cancel = h('button', { type: 'button' }, 'Discard changes');
  cancel.addEventListener('click', () => renderSettings(main));

  const form = h(
    'form',
    {
      oninput: () => {
        const n = Object.keys(current()).length;
        changedLabel.textContent = n ? `${n} unsaved change${n > 1 ? 's' : ''}` : 'No unsaved changes';
      },
      onsubmit: async (e) => {
        e.preventDefault();
        out.replaceChildren();
        const changes = current();
        if (!Object.keys(changes).length) return out.append(alertBox('info', 'Nothing changed', 'Edit a setting before applying.'));
        if (reason.value.trim().length < 3) {
          reason.setAttribute('aria-invalid', 'true');
          return out.append(errorBox({ message: 'Give a short reason. It is stored with the change in the audit trail.' }));
        }
        reason.removeAttribute('aria-invalid');
        const names = Object.keys(changes).map((k) => s.schema[k].label);
        const ok = await confirmDialog({ title: `Apply ${names.length} setting change${names.length > 1 ? 's' : ''}?`, body: `${names.join(', ')}. New decisions will record settings version ${s.version + 1}.`, confirmLabel: 'Apply changes', icon: 'settings' });
        if (!ok) return;
        await withBusy(apply, async () => {
          try {
            const r = await put('/api/admin/settings', { changes, reason: reason.value.trim(), confirm: true });
            toast(`Settings saved as version ${r.version}`);
            renderSettings(main);
          } catch (ex) {
            out.append(errorBox(ex));
          }
        });
      },
    },
    sections,
    h('div', { class: 'save-bar' }, field('Reason for change', reason, 'Required. Stored with the change in the audit trail.'), h('div', { class: 'actions' }, changedLabel, cancel, apply))
  );

  const history = card(
    { title: 'Change history', icon: 'history' },
    s.history.length
      ? h(
          'ol',
          { class: 'timeline' },
          s.history.map((v) =>
            h(
              'li',
              {},
              h('div', { class: 'actions' }, chip(`v${v.version}`, 'accent'), h('span', { class: 'muted small' }, `${formatTime(new Date(v.changed_at).toISOString())} · ${v.changed_by || 'system'}`)),
              v.reason ? h('p', { class: 'small', style: 'margin-top:6px' }, v.reason) : null,
              Object.keys(v.diff).length ? h('div', { class: 'diff' }, Object.entries(v.diff).map(([k, d]) => h('div', {}, `${k}: ${JSON.stringify(d.from)} → ${JSON.stringify(d.to)}`))) : null
            )
          )
        )
      : emptyState({ icon: 'history', title: 'No changes yet' })
  );

  main.replaceChildren(
    pageHead('Policy settings', `Currently version ${s.version}. Every change is validated, versioned and audited, and every decision records the version it was made under.`),
    card({}, out, form),
    h('div', { class: 'section' }, history)
  );
}

// ================================================================ audit
const UUIDISH = /^[0-9a-f]{8}-[0-9a-f-]{27}$/;
const EVENT_ICON = [
  [/^AUTH|^SESSION/, 'sign-in'], [/^USER/, 'users'], [/^DOC/, 'file'], [/^GRANT/, 'share'], [/^DOWNLOAD/, 'download'], [/^CONFIG/, 'settings'],
  [/^AUDIT/, 'audit'], [/^WATERMARK/, 'trace'], [/^REPORT/, 'export'], [/^SYSTEM|^SERVER/, 'server'], [/^ACCESS|^CSRF|^RATE|^REQUEST/, 'shield-alert'],
];
const eventIcon = (a) => (EVENT_ICON.find(([re]) => re.test(a)) || [null, 'activity'])[1];
const OUTCOME_KIND = { success: '', denied: 'danger', error: 'danger', info: 'warning' };

function detailLines(d) {
  const entries = Object.entries(d || {});
  if (!entries.length) return '—';
  return entries.slice(0, 4).map(([k, v]) => {
    let s = typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v);
    if (UUIDISH.test(s) || /^[0-9a-f]{40,}$/.test(s)) s = `${s.slice(0, 8)}…`;
    return h('div', {}, h('b', {}, `${k} `), s);
  });
}

export async function renderAudit(main) {
  const action = h('select', { 'aria-label': 'Filter by event' }, h('option', { value: '' }, 'All events'));
  const outcome = h('select', { 'aria-label': 'Filter by outcome' }, h('option', { value: '' }, 'All outcomes'), ['success', 'denied', 'error', 'info'].map((o) => h('option', { value: o }, `${o[0].toUpperCase()}${o.slice(1)}`)));
  const actor = searchBox({ placeholder: 'Filter by username', label: 'Filter by username' });
  const verifyOut = h('div', { 'aria-live': 'polite' });
  const body = h('div', {});
  const count = h('span', { class: 'count' });

  const PAGE = 50;
  let shown = [];
  const row = (e) =>
    h(
      'tr',
      {},
      h('td', { class: 'num mono-sm' }, String(e.seq)),
      h('td', { 'data-label': 'Event' }, h('div', { class: 'cell-main' }, h('span', { class: `dot-icon ${OUTCOME_KIND[e.outcome] || ''}` }, icon(eventIcon(e.action))), h('div', { class: 't' }, h('strong', { class: 'mono', style: 'font-size:12.5px' }, e.action), h('div', { class: 'sub', title: e.ts }, formatTime(e.ts))))),
      h('td', { 'data-label': 'Actor' }, e.actor_name || h('span', { class: 'muted' }, 'system'), e.actor_role ? h('div', { class: 'muted small' }, e.actor_role) : null),
      h('td', { 'data-label': 'Outcome' }, status(e.outcome)),
      h('td', { class: 'details-cell', 'data-label': 'Details', title: JSON.stringify(e.details, null, 1) }, detailLines(e.details)),
      h('td', { class: 'mono-sm', 'data-label': 'Hash', title: `prev ${e.prev_hash}\nhash ${e.hash}` }, `${e.hash.slice(0, 10)}…`),
      h('td', { class: 'actions-cell' }, h('div', { class: 'actions' }, e.action === 'GRANT_CREATE' && e.target_id ? revokeButton(e) : null))
    );

  /** Loads the newest page (more = false) or the next older page (more = true) using the API's beforeSeq cursor. */
  async function load(more = false) {
    const p = new URLSearchParams({ limit: String(PAGE) });
    if (action.value) p.set('action', action.value);
    if (outcome.value) p.set('outcome', outcome.value);
    if (actor.input.value.trim()) p.set('actor', actor.input.value.trim().toLowerCase());
    if (more && shown.length) p.set('beforeSeq', String(shown[shown.length - 1].seq));
    try {
      const r = await get(`/api/admin/audit?${p}`);
      if (action.options.length === 1) action.append(...r.actions.map((a) => h('option', { value: a }, a)));
      shown = more ? shown.concat(r.events) : r.events;
      const filtered = action.value || outcome.value || actor.input.value.trim();
      count.textContent = filtered ? `${shown.length} matching events shown` : `${shown.length} of ${r.total} events`;
      if (!shown.length) {
        body.replaceChildren(card({}, emptyState({ icon: 'audit', title: 'No events match', body: 'Try clearing the filters.' })));
        return;
      }
      const moreBtn = r.events.length === PAGE ? h('button', { type: 'button' }, icon('chevron-down', { cls: 'sm' }), 'Load older events') : null;
      moreBtn?.addEventListener('click', () => withBusy(moreBtn, () => load(true)));
      body.replaceChildren(
        h(
          'div',
          { class: 'card flush' },
          h(
            'div',
            { class: 'table-wrap' },
            h(
              'table',
              { class: 'stack-sm' },
              h('thead', {}, h('tr', {}, h('th', { class: 'num' }, '#'), h('th', {}, 'Event'), h('th', {}, 'Actor'), h('th', {}, 'Outcome'), h('th', {}, 'Details'), h('th', {}, 'Hash'), h('th', {}, h('span', { class: 'sr-only' }, 'Actions')))),
              h('tbody', {}, shown.map(row))
            )
          )
        ),
        moreBtn ? h('div', { class: 'actions', style: 'justify-content:center;margin-top:16px' }, moreBtn) : null
      );
    } catch (e) {
      body.replaceChildren(errorBox(e));
    }
  }

  // Incident response: an administrator can revoke any share from its GRANT_CREATE event.
  function revokeButton(e) {
    const btn = h('button', { type: 'button', class: 'small danger' }, icon('ban', { cls: 'sm' }), 'Revoke');
    btn.addEventListener('click', async () => {
      const who = e.details.recipient || 'the recipient';
      const ok = await confirmDialog({ title: `Revoke ${who}'s access to ${e.details.filename || 'this file'}?`, body: 'Use this for incident response. The owner will see that an administrator revoked it, and the action is audited.', confirmLabel: 'Revoke access', danger: true, icon: 'ban' });
      if (!ok) return;
      await withBusy(btn, async () => {
        try {
          await post(`/api/grants/${e.target_id}/revoke`, { confirm: true, reason: 'revoked by administrator (incident response)' });
          toast(`Revoked ${who}'s access`);
          load();
        } catch (ex) {
          toast(ex.code === 'CONFLICT' ? 'That share was already revoked.' : ex.message, { bad: true });
        }
      });
    });
    return btn;
  }

  const verifyBtn = h('button', { type: 'button', class: 'primary' }, icon('shield', { cls: 'sm' }), 'Verify chain');
  verifyBtn.addEventListener('click', () =>
    withBusy(verifyBtn, async () => {
      try {
        const r = await post('/api/admin/audit/verify');
        verifyOut.replaceChildren(
          decisionCard(
            { decision: r.ok ? 'allow' : 'deny', rule: r.rule, severity: r.severity, recommendedAction: r.recommendedAction, reason: r.ok ? `All ${r.evidence.checked} events verified: every HMAC matches and every link points to the previous event.` : 'The chain is broken. Events at or after the point shown were altered, inserted or removed.', evidence: r.evidence, engine: 'vaultshare-audit/1.0.0', latencyMs: r.latencyMs, id: r.decisionId },
            { title: r.ok ? 'Chain intact' : 'Tampering detected' }
          )
        );
        load();
      } catch (e) {
        verifyOut.replaceChildren(errorBox(e));
      }
    })
  );
  const exportBtn = h('button', { type: 'button' }, icon('export', { cls: 'sm' }), 'Export JSON');
  exportBtn.addEventListener('click', () =>
    withBusy(exportBtn, async () => {
      try {
        const { blob, name } = await fetchFile('/api/admin/audit/export');
        downloadBlob(blob, name);
        toast(`Exported ${name}`);
        load();
      } catch (e) {
        toast(e.message, { bad: true });
      }
    })
  );

  for (const el of [action, outcome]) el.addEventListener('change', () => load());
  let t;
  actor.input.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(() => load(), 300);
  });
  main.replaceChildren(
    pageHead('Audit trail', 'Append-only and hash-chained: each event carries an HMAC over its contents and the previous event, so any edit or deletion breaks the chain.', exportBtn, verifyBtn),
    verifyOut,
    h('div', { class: 'toolbar', style: 'margin-top:16px' }, actor.wrap, action, outcome, count),
    body
  );
  load();
}

// ================================================================ leak trace
export function renderTrace(main) {
  const out = h('div', { class: 'stack', 'aria-live': 'polite' });
  const input = h('input', { type: 'file', class: 'sr-only', id: 'trace-file', 'aria-label': 'Choose a leaked file' });
  const manual = h('input', { placeholder: 'VS1.…', spellcheck: 'false', style: 'font-family:var(--mono)' });

  async function verifyPayload(payload, source) {
    try {
      const r = await post('/api/admin/trace', { payload });
      return decisionCard({ decision: r.valid ? 'allow' : 'deny', rule: r.rule, severity: r.severity, recommendedAction: r.recommendedAction, reason: r.reason, evidence: r.evidence, engine: 'vaultshare-watermark/1.0.0', id: r.decisionId }, { title: r.valid ? 'Traced to a download' : 'Not verified', subject: source, openEvidence: true });
    } catch (e) {
      return errorBox(e);
    }
  }

  input.addEventListener('change', async () => {
    const f = input.files[0];
    if (!f) return;
    out.replaceChildren(alertBox('info', `Reading ${f.name} in this browser…`, 'Only the watermark reference is sent to the server.'));
    const bytes = new Uint8Array(await f.arrayBuffer());
    const payloads = await extractWatermarks(f.name, bytes);
    input.value = '';
    if (!payloads.length) {
      out.replaceChildren(decisionCard({ decision: 'deny', rule: 'NO_WATERMARK_FOUND', severity: 'low', reason: 'No VaultShare watermark was found. The file may not come from VaultShare, or the watermark was stripped.', recommendedAction: 'Check the file’s document properties or metadata by hand, or paste a reference below.', evidence: { file: f.name, bytes: bytes.length }, engine: 'browser extractor' }, { title: 'Nothing found' }));
      return;
    }
    out.replaceChildren(...(await Promise.all(payloads.map((p) => verifyPayload(p, `Found in ${f.name}`)))));
  });

  const chooseBtn = h('button', { type: 'button', class: 'primary' }, icon('plus', { cls: 'sm' }), 'Choose file');
  chooseBtn.addEventListener('click', (e) => (e.preventDefault(), input.click()));
  const verifyBtn = h('button', { class: 'primary', type: 'submit' }, 'Verify reference');

  main.replaceChildren(
    pageHead('Trace a leaked copy', 'Every opened file carries a signed watermark that identifies the exact download. The file is read only in this browser; just the watermark reference is sent for verification.'),
    h(
      'div',
      { class: 'grid-2' },
      card({}, input, h('label', { class: 'dropzone', for: 'trace-file' }, h('span', { class: 'dz-icon' }, icon('trace')), h('h3', {}, 'Choose the leaked file'), h('p', {}, 'Text, CSV, Markdown, PDF or PNG copies exported by VaultShare.'), chooseBtn)),
      card(
        { title: 'Or paste a reference', icon: 'hash', sub: 'Found in a PDF’s document properties or a PNG’s metadata.' },
        h(
          'form',
          {
            onsubmit: async (e) => {
              e.preventDefault();
              if (!manual.value.trim()) return out.replaceChildren(errorBox({ message: 'Paste a reference that starts with VS1.' }));
              await withBusy(verifyBtn, async () => out.replaceChildren(await verifyPayload(manual.value.trim(), 'Entered by hand')));
            },
          },
          field('Watermark reference', manual),
          verifyBtn
        )
      )
    ),
    h('div', { style: 'margin-top:20px' }, out)
  );
}
