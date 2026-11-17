// Operator / viewer dashboard. Every number comes from the existing APIs.
import { h, icon, pageHead, card, statCard, fileTile, status, emptyState, fingerprint, formatBytes, relative, formatTime } from '../ui.js';
import { get } from '../api.js';
import { state } from '../vault.js';

const ACTION_LABEL = { download: 'Opened', share: 'Shared', upload: 'Upload check', upload_content: 'Uploaded', decrypt: 'Integrity check' };

function greeting() {
  const hr = new Date().getHours();
  return hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening';
}

export async function renderDashboard(main) {
  const isOperator = state.user.role === 'operator';
  const [docs, hist, me] = await Promise.all([get('/api/documents'), get('/api/decisions?limit=1000'), get('/api/auth/me')]);
  const now = Date.now();
  const activeIn = docs.shared.filter((d) => d.grant.status === 'active');
  const expiringSoon = activeIn.filter((d) => d.grant.expiresAt && new Date(d.grant.expiresAt).getTime() - now < 24 * 3_600_000);
  const sharesOut = docs.owned.reduce((n, d) => n + d.activeShares, 0);

  const stats = isOperator
    ? [
        statCard({ icon: 'files', value: docs.owned.length, label: 'Files you own', hint: 'Stored encrypted', href: '#/documents?tab=owned' }),
        statCard({ icon: 'share', value: sharesOut, label: 'Active shares you gave', hint: 'Not expired or revoked', href: '#/documents?tab=owned' }),
        statCard({ icon: 'inbox', value: activeIn.length, label: 'Shared with you', hint: `${docs.shared.length} total, ${activeIn.length} still open`, href: '#/documents?tab=shared' }),
        statCard({ icon: 'clock', value: expiringSoon.length, label: 'Expiring within 24 h', hint: 'Shares you can still open', href: '#/documents?tab=shared' }),
      ]
    : [
        statCard({ icon: 'inbox', value: activeIn.length, label: 'Files you can open', hint: `${docs.shared.length} shared with you in total`, href: '#/documents' }),
        statCard({ icon: 'clock', value: expiringSoon.length, label: 'Expiring within 24 h', hint: 'Open them before access ends', href: '#/documents' }),
        statCard({ icon: 'decisions', value: hist.decisions.length, label: 'Decisions about you', hint: `${hist.decisions.filter((d) => d.decision === 'deny').length} denied`, href: '#/decisions' }),
      ];

  // recent documents: owned by upload time, shared by share time
  const recent = [
    ...docs.owned.map((d) => ({ d, at: d.uploadedAt, sub: `Uploaded ${relative(d.uploadedAt)} · ${formatBytes(d.sizeBytes)}`, chip: d.activeShares ? h('span', { class: 'chip accent' }, icon('share'), `${d.activeShares} shared`) : h('span', { class: 'chip' }, 'Private') })),
    ...docs.shared.map((d) => ({ d, at: d.grant.sharedAt, sub: `From ${d.ownerName} · shared ${relative(d.grant.sharedAt)}`, chip: status(d.grant.status) })),
  ]
    .sort((a, b) => new Date(b.at) - new Date(a.at))
    .slice(0, 5);

  const recentCard = card(
    { title: 'Recent documents', actions: h('a', { href: '#/documents', class: 'btn small' }, 'View all') },
    recent.length
      ? h('ul', { class: 'list' }, recent.map(({ d, sub, chip }) => h('li', {}, fileTile(d.extension), h('div', { class: 't' }, h('a', { href: `#/doc/${d.id}` }, d.filename), h('div', { class: 'sub' }, sub)), chip)))
      : emptyState({
          icon: isOperator ? 'upload-cloud' : 'inbox',
          title: isOperator ? 'No documents yet' : 'Nothing shared with you yet',
          body: isOperator ? 'Upload a file to encrypt it in your browser and store the sealed copy.' : 'Files appear here when someone shares them with you.',
          action: isOperator ? h('a', { class: 'btn primary', href: '#/upload' }, icon('upload', { cls: 'sm' }), 'Upload a file') : null,
        })
  );

  const activity = card(
    { title: 'Recent activity', sub: 'Your latest allow and deny decisions', actions: h('a', { href: '#/decisions', class: 'btn small' }, 'History') },
    hist.decisions.length
      ? h(
          'ul',
          { class: 'list' },
          hist.decisions.slice(0, 6).map((d) =>
            h(
              'li',
              {},
              h('span', { class: `dot-icon ${d.decision === 'allow' ? 'success' : 'danger'}` }, icon(d.decision === 'allow' ? 'check' : 'x', { label: d.decision === 'allow' ? 'Allowed' : 'Denied' })),
              h('div', { class: 't' }, h('strong', {}, `${ACTION_LABEL[d.action] || d.action}: ${d.subject || '—'}`), h('div', { class: 'sub' }, `${d.decision === 'allow' ? 'Allowed' : 'Denied'} · ${d.rule} · ${relative(d.ts)}`))
            )
          )
        )
      : emptyState({ icon: 'activity', title: 'No activity yet', body: 'Uploads, shares and downloads appear here with the rule that decided them.' })
  );

  const security = card(
    { title: 'Your security', icon: 'shield' },
    h(
      'dl',
      { class: 'dl' },
      h('dt', {}, 'Key fingerprint'),
      h('dd', {}, fingerprint(state.user.keyFingerprint)),
      h('dt', {}, 'Key version'),
      h('dd', {}, `v${state.user.keyVersion} · RSA-OAEP 2048`),
      h('dt', {}, 'Session'),
      h('dd', {}, me.session ? `Signs out after ${me.session.idleMinutes} min idle; ends ${formatTime(me.session.expiresAt)}` : '—'),
      h('dt', {}, 'Private key'),
      h('dd', {}, 'Held in memory for this tab only')
    )
  );

  const quick = card(
    { title: 'Quick actions' },
    h(
      'div',
      { class: 'quick' },
      isOperator ? h('a', { href: '#/upload' }, h('span', { class: 'dot-icon accent' }, icon('upload')), 'Upload and encrypt') : null,
      h('a', { href: '#/documents' }, h('span', { class: 'dot-icon accent' }, icon('files')), isOperator ? 'Browse documents' : 'Shared with me'),
      h('a', { href: '#/decisions' }, h('span', { class: 'dot-icon accent' }, icon('export')), 'Export a report'),
      h('a', { href: '#/account' }, h('span', { class: 'dot-icon accent' }, icon('key')), 'Key and password')
    )
  );

  main.replaceChildren(
    pageHead(
      `${greeting()}, ${state.user.username}`,
      isOperator ? 'Your encrypted workspace: files you own, what you have shared, and what others shared with you.' : 'Files other people have shared with you, and how long you can open them.',
      isOperator ? h('a', { class: 'btn primary', href: '#/upload' }, icon('upload', { cls: 'sm' }), 'Upload document') : null
    ),
    h('div', { class: 'stats' }, stats),
    h('div', { class: 'split' }, h('div', {}, recentCard, activity), h('div', {}, quick, security))
  );
}
