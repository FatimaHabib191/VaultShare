// App shell and router. Hash routes (#/path?query) keep the app a static,
// framework-free bundle that works under the strict CSP.
import { h, icon, avatar, roleChip, dropdown, errorBox, skeletonPage } from './ui.js';
import { setAuthLostHandler } from './api.js';
import { state, loadSession, isUnlocked, signOut } from './vault.js';
import { renderSignIn, renderUnlock, renderEnroll } from './views/auth.js';
import { renderDashboard } from './views/dashboard.js';
import { renderDocuments, renderUpload, renderDocument } from './views/documents.js';
import { renderHistory, renderAccount } from './views/history.js';
import { renderOverview, renderUsers, renderSettings, renderAudit, renderTrace } from './views/admin.js';

const root = document.getElementById('app');
let shell = null;

const NAV = {
  operator: [
    ['Workspace', [['#/dashboard', 'Dashboard', 'dashboard'], ['#/documents', 'Documents', 'files'], ['#/upload', 'Upload', 'upload']]],
    ['Evidence', [['#/decisions', 'My decisions', 'decisions']]],
    ['You', [['#/account', 'Account', 'user']]],
  ],
  viewer: [
    ['Workspace', [['#/dashboard', 'Dashboard', 'dashboard'], ['#/documents', 'Shared with me', 'files']]],
    ['Evidence', [['#/decisions', 'My decisions', 'decisions']]],
    ['You', [['#/account', 'Account', 'user']]],
  ],
  admin: [
    ['Manage', [['#/admin', 'Overview', 'overview'], ['#/admin/users', 'People', 'users'], ['#/admin/settings', 'Policy settings', 'settings']]],
    ['Evidence', [['#/admin/audit', 'Audit trail', 'audit'], ['#/admin/decisions', 'All decisions', 'decisions'], ['#/admin/trace', 'Trace a leak', 'trace']]],
    ['You', [['#/account', 'Account', 'user']]],
  ],
};

// [pattern, render, roles, title, skeleton kind]
const ROUTES = [
  [/^\/dashboard$/, (m, c) => renderDashboard(m, c), ['operator', 'viewer'], 'Dashboard', 'cards'],
  [/^\/documents$/, (m, c) => renderDocuments(m, c), ['operator', 'viewer'], 'Documents', 'cards'],
  [/^\/upload$/, (m, c) => renderUpload(m, c), ['operator'], 'Upload', 'cards'],
  [/^\/doc\/([0-9a-f-]{36})$/, (m, c) => renderDocument(m, c), ['operator', 'viewer'], 'Document', 'table'],
  [/^\/decisions$/, (m, c) => renderHistory(m, c), ['operator', 'viewer', 'admin'], 'My decisions', 'table'],
  [/^\/account$/, (m, c) => renderAccount(m, c), ['operator', 'viewer', 'admin'], 'Account', 'cards'],
  [/^\/admin$/, (m, c) => renderOverview(m, c), ['admin'], 'Overview', 'cards'],
  [/^\/admin\/users$/, (m, c) => renderUsers(m, c), ['admin'], 'People', 'table'],
  [/^\/admin\/settings$/, (m, c) => renderSettings(m, c), ['admin'], 'Policy settings', 'table'],
  [/^\/admin\/audit$/, (m, c) => renderAudit(m, c), ['admin'], 'Audit trail', 'table'],
  [/^\/admin\/decisions$/, (m, c) => renderHistory(m, { ...c, adminScope: true }), ['admin'], 'All decisions', 'table'],
  [/^\/admin\/trace$/, (m, c) => renderTrace(m, c), ['admin'], 'Trace a leak', 'cards'],
];

const home = () => (state.user.role === 'admin' ? '#/admin' : '#/dashboard');
const roleLabel = { admin: 'Administrator', operator: 'Operator', viewer: 'Viewer' };

function parseHash() {
  const raw = (location.hash || '').replace(/^#/, '') || home().slice(1);
  const [path, qs = ''] = raw.split('?');
  return { path, query: new URLSearchParams(qs) };
}

async function doSignOut() {
  await signOut();
  history.replaceState(null, '', '#/');
  start();
}

function brand(href) {
  return h('a', { class: 'brand', href, 'aria-label': 'VaultShare home' }, h('span', { class: 'brand-mark' }, icon('shield')), h('span', { class: 'brand-name' }, 'VaultShare'));
}

function buildShell() {
  const nav = h('nav', { class: 'nav', 'aria-label': 'Main' });
  for (const [group, links] of NAV[state.user.role]) {
    nav.append(h('div', { class: 'nav-group' }, group), ...links.map(([href, label, ic]) => h('a', { href }, icon(ic), h('span', {}, label))));
  }
  const signOutBtn = h('button', { type: 'button', class: 'ghost icon-btn small', 'aria-label': 'Sign out', 'data-tip': 'Sign out', onclick: doSignOut }, icon('logout', { cls: 'sm' }));
  const sidebar = h(
    'aside',
    { class: 'sidebar', id: 'sidebar', 'aria-label': 'Navigation' },
    brand(home()),
    nav,
    h(
      'div',
      { class: 'sidebar-foot' },
      h('div', { class: 'key-state', title: 'Your private key is held in memory for this tab only and cleared on reload or sign-out.' }, icon('unlock', { cls: 'sm' }), 'Key unlocked in this tab'),
      h('div', { class: 'account-card' }, avatar(state.user.username), h('div', { class: 'who' }, h('strong', {}, state.user.username), h('span', { class: 'muted small' }, roleLabel[state.user.role])), signOutBtn)
    )
  );
  const scrim = h('div', { class: 'scrim' });
  const menuBtn = h('button', { type: 'button', class: 'ghost icon-btn menu-toggle', 'aria-controls': 'sidebar', 'aria-expanded': 'false', 'aria-label': 'Open navigation' }, icon('menu'));
  const toggle = (open = !sidebar.classList.contains('open')) => {
    sidebar.classList.toggle('open', open);
    scrim.classList.toggle('show', open);
    menuBtn.setAttribute('aria-expanded', String(open));
  };
  menuBtn.addEventListener('click', () => toggle());
  scrim.addEventListener('click', () => toggle(false));
  sidebar.addEventListener('click', (e) => e.target.closest('a') && toggle(false));
  document.addEventListener('keydown', (e) => e.key === 'Escape' && sidebar.classList.contains('open') && toggle(false));

  const crumbs = h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' });

  // Header search: operators/viewers search their files, admins search people.
  const isAdmin = state.user.role === 'admin';
  const searchTarget = isAdmin ? '#/admin/users' : '#/documents';
  const searchInput = h('input', { type: 'search', placeholder: isAdmin ? 'Search people' : 'Search files', 'aria-label': isAdmin ? 'Search people' : 'Search files', autocomplete: 'off' });
  let searchTimer;
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const q = searchInput.value.trim();
      const target = `${searchTarget}${q ? `?q=${encodeURIComponent(q)}` : ''}`;
      if (location.hash.split('?')[0] === searchTarget) {
        history.replaceState(null, '', target);
        window.dispatchEvent(new CustomEvent('vs:search', { detail: q }));
      } else location.hash = target;
    }, 220);
  });
  const search = h('div', { class: 'topbar-search', role: 'search' }, icon('search', { cls: 'sm' }), searchInput);

  const acctBtn = h('button', { type: 'button', class: 'ghost', 'aria-label': `Account menu for ${state.user.username}`, style: 'padding:0 6px;gap:8px' }, avatar(state.user.username, { small: true }), icon('chevron-down', { cls: 'sm' }));
  const acctMenu = dropdown(
    acctBtn,
    [
      { label: 'Account and key', icon: 'user', href: '#/account' },
      { label: 'Sign out', icon: 'logout', danger: true, onclick: doSignOut },
    ],
    { head: [h('strong', {}, state.user.username), roleChip(state.user.role)] }
  );

  const topbar = h('header', { class: 'topbar' }, menuBtn, crumbs, search, h('div', { class: 'topbar-actions' }, acctMenu));
  const content = h('main', { class: 'content', id: 'main', tabindex: '-1' });
  root.replaceChildren(h('div', { class: 'app' }, sidebar, scrim, h('div', { class: 'main-col' }, topbar, content)));
  return { nav, content, crumbs, searchInput, searchTarget };
}

function setCrumbs(items) {
  shell.crumbs.replaceChildren(
    ...items.flatMap((it, i) => {
      const last = i === items.length - 1;
      const node = last ? h('span', { class: 'current', 'aria-current': 'page' }, it.label) : h('a', { href: it.href }, it.label);
      return i ? [icon('chevron-right'), node] : [node];
    })
  );
  document.title = `${items[items.length - 1].label} · VaultShare`;
}

async function route() {
  if (!state.user || !isUnlocked()) return;
  const { path, query } = parseHash();
  const r = ROUTES.find(([re, , roles]) => re.test(path) && roles.includes(state.user.role));
  if (!r) {
    history.replaceState(null, '', home());
    return route();
  }
  if (!shell) shell = buildShell();
  const hash = `#${path}`;
  for (const a of shell.nav.querySelectorAll('a')) {
    const href = a.getAttribute('href');
    const current = hash === href || (path.startsWith('/doc/') && href === '#/documents');
    if (current) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  if (`#${path}` === shell.searchTarget) shell.searchInput.value = query.get('q') || '';
  else shell.searchInput.value = '';
  const [, render, , title, sk] = r;
  setCrumbs([{ label: title }]);
  shell.content.replaceChildren(skeletonPage(sk));
  try {
    await render(shell.content, { params: r[0].exec(path), query, setCrumbs });
  } catch (e) {
    shell.content.replaceChildren(errorBox(e));
  }
  shell.content.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

async function start(message) {
  shell = null;
  const done = () => {
    const p = location.hash.replace(/^#/, '');
    if (!p || p === '/' || p === '/enroll') history.replaceState(null, '', home());
    route();
  };
  if (location.hash === '#/enroll' && !state.user) return renderEnroll(root, { onDone: done });
  if (!state.user && !(await loadSession())) return renderSignIn(root, { onDone: done, message });
  if (!isUnlocked()) return renderUnlock(root, { onDone: done });
  done();
}

setAuthLostHandler(async (err) => {
  Object.assign(state, { user: null, privateKey: null, publicKey: null });
  start(err.code === 'SESSION_EXPIRED' ? 'Your session ended after a period of inactivity. Sign in again.' : 'Sign in to continue.');
});

window.addEventListener('hashchange', () => {
  if (!state.user) return start();
  route();
});

start();
