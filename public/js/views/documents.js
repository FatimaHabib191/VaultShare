import * as C from '/shared/crypto-core.js';
import {
  h, icon, pageHead, card, chip, status, fileTile, emptyState, errorBox, alertBox, decisionCard, toast, confirmDialog, field,
  fingerprint, downloadBlob, formatBytes, formatTime, formatDate, relative, searchBox, segmented, prefs, withBusy,
} from '../ui.js';
import { get, post, put, del } from '../api.js';
import { state } from '../vault.js';
import { uploadRequest, applyWatermark, TYPES } from '../files.js';

const TYPE_GROUPS = [
  ['all', 'All types', null],
  ['doc', 'Text and Markdown', ['txt', 'md']],
  ['sheet', 'Spreadsheets (CSV)', ['csv']],
  ['pdf', 'PDF', ['pdf']],
  ['image', 'Images', ['png', 'jpg', 'jpeg']],
];
const SORTS = [
  ['new', 'Newest first'],
  ['old', 'Oldest first'],
  ['name', 'Name A–Z'],
  ['size', 'Largest first'],
];

let searchListener = null;

// ================================================================ list
export async function renderDocuments(main, { query }) {
  const data = await get('/api/documents');
  const isOperator = state.user.role === 'operator';

  const items = [
    ...data.owned.map((d) => ({ ...d, kind: 'owned', owner: 'You', at: d.uploadedAt, badge: () => (d.activeShares ? chip(`Shared with ${d.activeShares}`, 'accent', 'share') : chip('Private', 'neutral', 'lock')) })),
    ...data.shared.map((d) => ({ ...d, kind: 'shared', owner: d.ownerName, at: d.grant.sharedAt, badge: () => status(d.grant.status) })),
  ];

  const ui = {
    tab: isOperator ? (['owned', 'shared'].includes(query.get('tab')) ? query.get('tab') : 'all') : 'shared',
    q: query.get('q') || '',
    type: 'all',
    sort: 'new',
    view: prefs.get('docView', 'grid'),
  };

  const results = h('div', { 'aria-live': 'polite' });
  const count = h('span', { class: 'count' });
  const search = searchBox({ placeholder: 'Search by name or owner', value: ui.q, label: 'Search documents', oninput: (v) => ((ui.q = v), draw()) });
  const typeSel = h('select', { 'aria-label': 'Filter by file type' }, TYPE_GROUPS.map(([v, l]) => h('option', { value: v }, l)));
  typeSel.addEventListener('change', () => ((ui.type = typeSel.value), draw()));
  const sortSel = h('select', { 'aria-label': 'Sort documents' }, SORTS.map(([v, l]) => h('option', { value: v }, l)));
  sortSel.addEventListener('change', () => ((ui.sort = sortSel.value), draw()));
  const viewToggle = segmented(
    [
      { value: 'grid', label: 'Grid view', icon: 'grid' },
      { value: 'list', label: 'List view', icon: 'list' },
    ],
    ui.view,
    (v) => {
      ui.view = v;
      prefs.set('docView', v);
      draw();
    },
    'Layout'
  );

  // header search box drives the same filter
  if (searchListener) window.removeEventListener('vs:search', searchListener);
  searchListener = (e) => {
    ui.q = e.detail;
    search.input.value = e.detail;
    draw();
  };
  window.addEventListener('vs:search', searchListener);

  const tabs = isOperator
    ? h(
        'div',
        { class: 'tabs', role: 'tablist', 'aria-label': 'Document sets' },
        [
          ['all', 'All', items.length],
          ['owned', 'My files', data.owned.length],
          ['shared', 'Shared with me', data.shared.length],
        ].map(([v, l, n]) => {
          const b = h('button', { type: 'button', role: 'tab', 'aria-selected': String(ui.tab === v) }, l, h('span', { class: 'badge-count' }, String(n)));
          b.addEventListener('click', () => {
            ui.tab = v;
            tabs.querySelectorAll('[role=tab]').forEach((t) => t.setAttribute('aria-selected', String(t === b)));
            draw();
          });
          return b;
        })
      )
    : null;

  function filtered() {
    const q = ui.q.trim().toLowerCase();
    const group = TYPE_GROUPS.find(([v]) => v === ui.type)[2];
    const list = items.filter(
      (d) =>
        (ui.tab === 'all' || d.kind === ui.tab) &&
        (!group || group.includes(d.extension)) &&
        (!q || d.filename.toLowerCase().includes(q) || d.owner.toLowerCase().includes(q))
    );
    const by = {
      new: (a, b) => new Date(b.at) - new Date(a.at),
      old: (a, b) => new Date(a.at) - new Date(b.at),
      name: (a, b) => a.filename.localeCompare(b.filename),
      size: (a, b) => b.sizeBytes - a.sizeBytes,
    }[ui.sort];
    return list.sort(by);
  }

  function gridView(list) {
    return h(
      'div',
      { class: 'doc-grid' },
      list.map((d) =>
        h(
          'a',
          { class: 'doc-card', href: `#/doc/${d.id}`, 'aria-label': `${d.filename}, ${d.kind === 'owned' ? 'owned by you' : `from ${d.owner}`}` },
          h('div', { class: 'cell-main' }, fileTile(d.extension), h('div', { class: 't' }, h('div', { class: 'name', title: d.filename }, d.filename), h('div', { class: 'meta' }, `${formatBytes(d.sizeBytes)} · ${d.kind === 'owned' ? 'You' : d.owner}`))),
          h('div', {}, d.badge()),
          h('div', { class: 'foot' }, h('span', {}, d.kind === 'owned' ? `Uploaded ${formatDate(d.at)}` : d.grant.expiresAt && d.grant.status === 'active' ? `Expires ${relative(d.grant.expiresAt)}` : `Shared ${formatDate(d.at)}`), d.kind === 'shared' ? h('span', {}, `${d.grant.downloadCount}/${d.grant.maxDownloads} downloads`) : h('span', {}, icon('lock', { cls: 'sm', label: 'Encrypted' })))
        )
      )
    );
  }

  function listView(list) {
    return h(
      'div',
      { class: 'card flush' },
      h(
        'div',
        { class: 'table-wrap' },
        h(
          'table',
          { class: 'stack-sm' },
          h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Owner'), h('th', { class: 'num' }, 'Size'), h('th', {}, 'Date'), h('th', {}, 'Status'), h('th', {}, h('span', { class: 'sr-only' }, 'Actions')))),
          h(
            'tbody',
            {},
            list.map((d) =>
              h(
                'tr',
                {},
                h('td', {}, h('div', { class: 'cell-main' }, fileTile(d.extension), h('div', { class: 't' }, h('a', { href: `#/doc/${d.id}`, title: d.filename }, d.filename), h('div', { class: 'sub' }, d.extension.toUpperCase())))),
                h('td', { 'data-label': 'Owner' }, d.owner),
                h('td', { class: 'num', 'data-label': 'Size' }, formatBytes(d.sizeBytes)),
                h('td', { 'data-label': d.kind === 'owned' ? 'Uploaded' : 'Shared' }, formatDate(d.at)),
                h('td', { 'data-label': 'Status' }, d.badge()),
                h('td', { class: 'actions-cell' }, h('div', { class: 'actions' }, h('a', { class: 'btn small', href: `#/doc/${d.id}` }, 'Open')))
              )
            )
          )
        )
      )
    );
  }

  function draw() {
    const list = filtered();
    const scoped = items.filter((d) => ui.tab === 'all' || d.kind === ui.tab);
    count.textContent = `${list.length} of ${scoped.length} document${scoped.length === 1 ? '' : 's'}`;
    if (!scoped.length) {
      results.replaceChildren(
        card(
          {},
          emptyState(
            ui.tab === 'shared' || !isOperator
              ? { icon: 'inbox', title: 'Nothing shared with you yet', body: 'When someone shares a file with you, it appears here until the share expires or is revoked.' }
              : { icon: 'upload-cloud', title: 'No documents yet', body: 'Upload a file to encrypt it in your browser and store only the sealed copy.', action: h('a', { class: 'btn primary', href: '#/upload' }, icon('upload', { cls: 'sm' }), 'Upload a file') }
          )
        )
      );
      return;
    }
    if (!list.length) {
      const clear = h('button', { type: 'button' }, 'Clear filters');
      clear.addEventListener('click', () => {
        ui.q = '';
        ui.type = 'all';
        search.input.value = '';
        typeSel.value = 'all';
        draw();
      });
      results.replaceChildren(card({}, emptyState({ icon: 'search', title: 'No documents match', body: 'Try a different name or file type.', action: clear })));
      return;
    }
    results.replaceChildren(ui.view === 'grid' ? gridView(list) : listView(list));
  }

  main.replaceChildren(
    pageHead(
      isOperator ? 'Documents' : 'Shared with me',
      isOperator ? 'Everything you own and everything shared with you. Files are stored encrypted; only people you share with can open them.' : 'Files other people have shared with you. Each share has its own expiry and download limit.',
      isOperator ? h('a', { class: 'btn primary', href: '#/upload' }, icon('upload', { cls: 'sm' }), 'Upload') : null
    ),
    tabs,
    h('div', { class: 'toolbar' }, search.wrap, typeSel, sortSel, viewToggle, count),
    results
  );
  draw();
}

// ================================================================ upload
const STEP_LABELS = ['Checking type, size and contents', 'Encrypting with a new AES-256-GCM key', 'Wrapping the key with your public key', 'Uploading the sealed copy'];

async function describeForUpload(file, maxBytes) {
  // Oversized files are not read in full: the first 64 KB is enough for the server's content check,
  // and the server still records the size rejection.
  const slice = file.size > maxBytes ? file.slice(0, 65536) : file;
  const bytes = new Uint8Array(await slice.arrayBuffer());
  const req = uploadRequest(file.name, bytes);
  req.sizeBytes = file.size;
  return { req, bytes: file.size > maxBytes ? null : bytes };
}

export async function renderUpload(main) {
  const policy = await get('/api/documents/policy');
  const maxBytes = policy.maxFileSizeMb * 1024 * 1024;
  const accept = policy.allowedExtensions.map((e) => `.${e}`).join(',');
  const input = h('input', { type: 'file', class: 'sr-only', id: 'file-input', multiple: true, accept, 'aria-label': 'Choose files to upload' });
  const queueList = h('ul', { class: 'queue' });
  const queueCard = card({ title: 'Upload queue', sub: 'Files are processed one at a time. Nothing is stored until a step reports success.' }, queueList);
  queueCard.hidden = true;
  let running = false;
  const queue = [];

  const chooseBtn = h('button', { type: 'button', class: 'primary' }, icon('plus', { cls: 'sm' }), 'Choose files');
  chooseBtn.addEventListener('click', (e) => {
    e.preventDefault();
    input.click();
  });
  const drop = h(
    'label',
    { class: 'dropzone', for: 'file-input' },
    h('span', { class: 'dz-icon' }, icon('upload-cloud')),
    h('h3', {}, 'Drag files here, or choose them'),
    h('p', {}, 'Each file is checked by the server, then encrypted in this browser before anything is uploaded.'),
    chooseBtn,
    h('div', { class: 'chips' }, policy.allowedExtensions.map((e) => chip(`.${e}`, 'outline', null, 'mono')), chip(`Up to ${policy.maxFileSizeMb} MB`, 'accent'))
  );
  drop.addEventListener('dragover', (e) => (e.preventDefault(), drop.classList.add('over')));
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    add([...e.dataTransfer.files]);
  });
  input.addEventListener('change', () => {
    add([...input.files]);
    input.value = '';
  });

  function add(files) {
    for (const file of files) {
      const item = { file, state: 'queued', li: h('li', {}) };
      queue.push(item);
      queueList.append(item.li);
      draw(item);
    }
    queueCard.hidden = !queue.length;
    run();
  }

  function draw(item, { step = 0, decision, error, docId } = {}) {
    const { file } = item;
    const ext = (/\.([A-Za-z0-9]{1,8})$/.exec(file.name)?.[1] || '').toLowerCase();
    const pct = item.state === 'done' ? 100 : item.state === 'running' ? Math.round((step / STEP_LABELS.length) * 100) + 8 : item.state === 'failed' ? 100 : 0;
    const chipNode = {
      queued: chip('Waiting', 'neutral', 'clock'),
      running: chip('Working', 'accent', 'loader'),
      done: chip('Encrypted and stored', 'success', 'check-circle'),
      failed: chip(decision ? 'Rejected' : 'Failed', 'danger', 'x-circle'),
    }[item.state];
    const actions = h('div', { class: 'actions' });
    if (item.state === 'done' && docId) actions.append(h('a', { class: 'btn small', href: `#/doc/${docId}` }, isShareable() ? 'Open and share' : 'Open'));
    if (item.state === 'failed' && !decision) {
      const retry = h('button', { type: 'button', class: 'small' }, icon('refresh', { cls: 'sm' }), 'Retry');
      retry.addEventListener('click', () => {
        item.state = 'queued';
        draw(item);
        run();
      });
      actions.append(retry);
    }
    if (item.state === 'failed' || item.state === 'done') {
      const rm = h('button', { type: 'button', class: 'ghost icon-btn small', 'aria-label': `Remove ${file.name} from the list`, 'data-tip': 'Remove' }, icon('x', { cls: 'sm' }));
      rm.addEventListener('click', () => {
        item.li.remove();
        queue.splice(queue.indexOf(item), 1);
        queueCard.hidden = !queue.length;
      });
      actions.append(rm);
    }
    const stepText =
      item.state === 'running' ? `Step ${step + 1} of ${STEP_LABELS.length}: ${STEP_LABELS[step]}` : item.state === 'queued' ? 'Waiting to start' : item.state === 'done' ? 'Stored as ciphertext; the server cannot read it.' : decision ? `${file.name} was not encrypted or stored. The rejection is in your decision history.` : 'Something went wrong before the file was stored.';
    item.li.replaceChildren(
      h('div', { class: 'q-row' }, fileTile(ext), h('div', { class: 't' }, h('strong', { title: file.name }, file.name), h('div', { class: 'sub' }, `${formatBytes(file.size)} · ${stepText}`)), chipNode, actions),
      h('div', { class: `progress ${item.state === 'done' ? 'done' : item.state === 'failed' ? 'fail' : ''}`, role: 'progressbar', 'aria-label': `${file.name} progress`, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(Math.min(pct, 100)) }, h('span', { style: `width:${Math.min(pct, 100)}%` })),
      item.state === 'done' && decision
        ? h('div', { class: 'q-detail actions small muted' }, icon('shield', { cls: 'sm' }), 'Decision', chip(decision.rule, 'outline', null, 'mono'), `settings v${decision.configVersion}`, h('a', { href: '#/decisions' }, 'View in history'))
        : decision || error
          ? h('div', { class: 'q-detail' }, decision ? decisionCard(decision, { title: 'Rejected' }) : errorBox(error))
          : null
    );
  }
  const isShareable = () => state.user.role === 'operator';

  async function run() {
    if (running) return;
    running = true;
    try {
      let item;
      while ((item = queue.find((i) => i.state === 'queued'))) await process(item);
    } finally {
      running = false;
    }
  }

  async function process(item) {
    item.state = 'running';
    draw(item, { step: 0 });
    let init;
    try {
      const { req, bytes } = await describeForUpload(item.file, maxBytes);
      try {
        init = await post('/api/documents', req);
      } catch (e) {
        item.state = 'failed';
        return draw(item, e.decision ? { decision: e.decision } : { error: e });
      }
      draw(item, { step: 1 });
      const dek = await C.generateDek();
      const container = await C.encryptDocument(dek, bytes, init.binding);
      draw(item, { step: 2 });
      const wrappedKey = await C.wrapDekFor(dek, state.publicKey);
      draw(item, { step: 3 });
      const res = await put(`/api/documents/${init.id}/content`, { ciphertext: C.toB64(container), wrappedKey });
      item.state = 'done';
      draw(item, { docId: init.id, decision: res.decision });
      toast(`Uploaded ${item.file.name}`);
    } catch (e) {
      item.state = 'failed';
      draw(item, e.decision ? { decision: e.decision } : { error: e });
    }
  }

  const how = card(
    { title: 'How your upload is protected', icon: 'shield' },
    h(
      'ol',
      { class: 'steps' },
      STEP_LABELS.map((s) => h('li', { class: 'done' }, h('span', { class: 's-dot' }, icon('check')), s))
    ),
    h('div', { class: 'card-foot' }, h('dl', { class: 'dl' }, h('dt', {}, 'Server sees'), h('dd', {}, 'File name, type, size, first 8 bytes, the ciphertext and your wrapped key'), h('dt', {}, 'Server never sees'), h('dd', {}, 'The file contents, your password or your private key')))
  );

  main.replaceChildren(
    pageHead('Upload documents', 'Files are encrypted in your browser with a fresh key for each file. The server checks the type, size and structure of what it receives.'),
    h('div', { class: 'split' }, h('div', {}, card({}, input, drop), queueCard), h('div', {}, how))
  );
}

// ================================================================ detail
export async function renderDocument(main, { params, setCrumbs }) {
  const id = params[1];
  let data;
  try {
    data = await get(`/api/documents/${id}`);
  } catch (e) {
    setCrumbs([{ label: 'Documents', href: '#/documents' }, { label: 'Not available' }]);
    main.replaceChildren(
      card({}, emptyState({ icon: 'lock', title: 'This document is not available', body: 'It does not exist, was deleted, or has not been shared with you.', action: h('a', { class: 'btn', href: '#/documents' }, icon('arrow-left', { cls: 'sm' }), 'Back to documents') })),
      h('div', { style: 'margin-top:16px' }, errorBox(e))
    );
    return;
  }
  const d = data.document;
  setCrumbs([{ label: state.user.role === 'viewer' ? 'Shared with me' : 'Documents', href: '#/documents' }, { label: d.filename }]);
  const outcome = h('div', { class: 'stack', 'aria-live': 'polite' });
  const myGrant = data.isOwner ? null : data.grants[0];

  const accessList = (g) =>
    h(
      'dl',
      { class: 'dl' },
      h('dt', {}, 'Status'),
      h('dd', {}, status(g.status)),
      h('dt', {}, 'Access ends'),
      h('dd', {}, g.expiresAt ? `${formatTime(g.expiresAt)} (${relative(g.expiresAt)})` : 'No expiry'),
      h('dt', {}, 'Downloads'),
      h('dd', {}, `${g.downloadCount} of ${g.maxDownloads} used`),
      g.revokedAt ? [h('dt', {}, 'Revoked'), h('dd', {}, formatTime(g.revokedAt))] : null
    );
  const accessBox = h('div', {}, myGrant ? accessList(myGrant) : null);
  const heroStatus = h('span', { style: 'display:contents' }, myGrant ? status(myGrant.status) : null);
  const refreshAccess = async () => {
    if (data.isOwner) return;
    try {
      const g = (await get(`/api/documents/${id}`)).grants[0];
      accessBox.replaceChildren(accessList(g));
      heroStatus.replaceChildren(status(g.status));
    } catch {
      /* keep the last known state */
    }
  };

  const openBtn = h('button', { type: 'button', class: 'primary' }, icon('unlock', { cls: 'sm' }), 'Open and decrypt');
  openBtn.addEventListener('click', () => withBusy(openBtn, open));
  async function open() {
    outcome.replaceChildren(alertBox('info', 'Requesting access…', 'The server checks your share before releasing the encrypted file.'));
    try {
      const res = await post(`/api/documents/${id}/download`);
      const dek = await C.unwrapDek(res.wrappedKey, state.privateKey);
      let plain;
      try {
        plain = await C.decryptDocument(dek, C.fromB64(res.ciphertext), res.binding);
      } catch (ex) {
        const check = ex.message;
        let rec = { decision: 'deny', rule: 'INTEGRITY_CHECK_FAILED', severity: 'high', reason: 'The ciphertext failed its AES-GCM authentication check. It was altered after encryption; nothing was decrypted.', evidence: { documentId: id, failedCheck: check }, engine: C.CRYPTO_VERSION };
        try {
          rec = (await post(`/api/documents/${id}/integrity-failure`, { downloadId: res.watermark.downloadId, check })).decision;
        } catch {
          /* still show the local result if reporting fails */
        }
        outcome.replaceChildren(decisionCard(rec, { title: 'Rejected', subject: 'This event was recorded in the audit trail.' }));
        return;
      }
      const marked = await applyWatermark({ bytes: plain, ext: d.extension, filename: d.filename, watermark: res.watermark });
      const blob = new Blob([marked.bytes], { type: marked.mime });
      const url = URL.createObjectURL(blob);
      const kind = TYPES[d.extension].kind;
      const preview = h(
        'div',
        { class: 'preview' },
        kind === 'text' ? h('pre', {}, new TextDecoder().decode(marked.bytes)) : kind === 'image' ? h('img', { src: url, alt: `Watermarked preview of ${d.filename}` }) : h('iframe', { src: url, title: `Preview of ${d.filename}` })
      );
      const save = h('button', { type: 'button', class: 'primary' }, icon('download', { cls: 'sm' }), `Save ${marked.filename}`);
      save.addEventListener('click', () => downloadBlob(blob, marked.filename));
      outcome.replaceChildren(
        decisionCard(res.decision, { subject: `Decrypted in your browser and watermarked: ${marked.method}.` }),
        card({ title: 'Your watermarked copy', sub: res.watermark.label, actions: save }, preview)
      );
    } catch (e) {
      outcome.replaceChildren(e.decision ? decisionCard(e.decision, { subject: e.message !== e.decision.reason ? e.message : null }) : errorBox(e));
    } finally {
      refreshAccess();
    }
  }

  const details = card(
    { title: 'Details', icon: 'info' },
    h(
      'dl',
      { class: 'dl' },
      h('dt', {}, 'Owner'),
      h('dd', {}, data.isOwner ? 'You' : d.ownerName),
      h('dt', {}, 'Type'),
      h('dd', {}, `${d.extension.toUpperCase()} · ${d.mimeType}`),
      h('dt', {}, 'Size'),
      h('dd', {}, `${formatBytes(d.sizeBytes)} (ciphertext ${formatBytes(d.cipherBytes)})`),
      h('dt', {}, 'Uploaded'),
      h('dd', {}, formatTime(d.uploadedAt)),
      h('dt', {}, 'Encryption'),
      h('dd', {}, 'AES-256-GCM, 96-bit IV, bound to this document and owner'),
      h('dt', {}, 'Ciphertext SHA-256'),
      h('dd', { class: 'mono' }, d.cipherSha256 || '—')
    )
  );

  const hero = h(
    'header',
    { class: 'page-head' },
    h(
      'div',
      { class: 'doc-hero' },
      fileTile(d.extension, { lg: true }),
      h(
        'div',
        { style: 'min-width:0' },
        h('h1', { title: d.filename }, d.filename),
        h('div', { class: 'meta' }, data.isOwner ? chip('You own this file', 'accent', 'key') : h('span', {}, `Shared by ${d.ownerName}`), heroStatus, h('span', {}, formatBytes(d.sizeBytes)), h('span', {}, `Uploaded ${formatDate(d.uploadedAt)}`))
      )
    ),
    d.status === 'active' ? h('div', { class: 'actions' }, openBtn) : null
  );

  const left = [d.status === 'deleted' ? alertBox('danger', 'This file was deleted', 'The owner deleted it. Its ciphertext and wrapped keys were destroyed.') : null, outcome];
  let right;
  if (data.isOwner) {
    const policy = await get('/api/documents/policy');
    const refresh = () => renderDocument(main, { params, setCrumbs });
    left.push(grantsCard(data, refresh));
    right = [shareCard(d, policy, refresh), details, dangerZone(d)];
  } else {
    left.push(card({ title: 'Your access', icon: 'key' }, accessBox));
    right = [details];
  }
  main.replaceChildren(hero, h('div', { class: 'split' }, h('div', {}, left.filter(Boolean)), h('div', {}, right)));
}

function grantsCard(data, refresh) {
  const shares = data.grants.filter((g) => !g.isOwner);
  const active = shares.filter((g) => g.status === 'active').length;
  return card(
    { title: 'Who has access', icon: 'users', sub: shares.length ? `${active} active of ${shares.length} share${shares.length === 1 ? '' : 's'}` : null, flush: !!shares.length },
    shares.length
      ? h(
          'div',
          { class: 'table-wrap', style: 'margin-top:4px' },
          h(
            'table',
            { class: 'stack-sm' },
            h('thead', {}, h('tr', {}, h('th', {}, 'Recipient'), h('th', {}, 'Status'), h('th', {}, 'Access ends'), h('th', { class: 'num' }, 'Downloads'), h('th', {}, h('span', { class: 'sr-only' }, 'Actions')))),
            h(
              'tbody',
              {},
              shares.map((g) => {
                const revoke =
                  g.status === 'active' || g.status === 'key_mismatch'
                    ? h('button', { type: 'button', class: 'small danger' }, icon('ban', { cls: 'sm' }), 'Revoke')
                    : null;
                revoke?.addEventListener('click', async () => {
                  const ok = await confirmDialog({ title: `Revoke ${g.recipientName}'s access?`, body: 'They will be denied on their next attempt to open the file. Copies they already saved stay watermarked to them.', confirmLabel: 'Revoke access', danger: true, icon: 'ban' });
                  if (!ok) return;
                  await withBusy(revoke, async () => {
                    try {
                      await post(`/api/grants/${g.id}/revoke`, { confirm: true, reason: 'revoked by owner' });
                      toast(`Revoked ${g.recipientName}'s access`);
                      refresh();
                    } catch (e) {
                      toast(e.message, { bad: true });
                    }
                  });
                });
                return h(
                  'tr',
                  {},
                  h('td', {}, h('div', { class: 'cell-main' }, h('span', { class: 'avatar sm' }, g.recipientName.slice(0, 2)), h('div', { class: 't' }, h('strong', {}, g.recipientName), h('div', { class: 'sub mono-sm' }, `key ${g.keyFingerprint.slice(0, 12)}`)))),
                  h('td', { 'data-label': 'Status' }, status(g.status), g.revokedBy ? h('div', { class: 'muted small' }, `by ${g.revokedBy}`) : null),
                  h('td', { 'data-label': 'Access ends', title: formatTime(g.expiresAt) }, relative(g.expiresAt)),
                  h('td', { class: 'num', 'data-label': 'Downloads' }, `${g.downloadCount} / ${g.maxDownloads}`),
                  h('td', { class: 'actions-cell' }, h('div', { class: 'actions' }, revoke))
                );
              })
            )
          )
        )
      : emptyState({ icon: 'share', title: 'Not shared yet', body: 'Use Share to give someone time-limited access. Only they will be able to open it.' })
  );
}

function shareCard(doc, policy, refresh) {
  const out = h('div', { 'aria-live': 'polite', style: 'margin-top:16px' });
  const select = h('select', { required: true }, h('option', { value: '' }, 'Loading people…'));
  const fpBox = h('div', { class: 'field', hidden: true });
  const expiry = h(
    'select',
    {},
    [
      ['1', '1 minute (demo)'],
      ['60', '1 hour'],
      ['1440', '1 day'],
      ['10080', '7 days'],
      ['custom', 'Custom…'],
    ].map(([v, l]) => h('option', { value: v }, l))
  );
  expiry.value = String(Math.min(1440, policy.maxGrantHours * 60));
  if (![...expiry.options].some((o) => o.value === expiry.value)) expiry.value = '60';
  const minutes = h('input', { type: 'number', min: '1', step: '1', value: '120', 'aria-label': 'Custom expiry in minutes' });
  const minutesField = field('Custom length (minutes)', minutes);
  minutesField.hidden = true;
  expiry.addEventListener('change', () => (minutesField.hidden = expiry.value !== 'custom'));
  const downloads = h('input', { type: 'number', min: '1', max: String(policy.maxDownloads), step: '1', value: '3' });
  let people = [];

  get('/api/directory')
    .then((r) => {
      people = r.users;
      select.replaceChildren(h('option', { value: '' }, people.length ? 'Choose a person' : 'No one else has set up an account yet'), ...people.map((u) => h('option', { value: u.id }, `${u.username} (${u.role})`)));
    })
    .catch((e) => out.replaceChildren(errorBox(e)));
  select.addEventListener('change', () => {
    const p = people.find((u) => u.id === select.value);
    fpBox.hidden = !p;
    fpBox.replaceChildren(...(p ? [h('span', { class: 'label' }, `${p.username}'s key fingerprint`), fingerprint(p.keyFingerprint), h('span', { class: 'hint' }, `Ask ${p.username} to compare this with their Account page before you share anything sensitive.`)] : []));
  });

  const btn = h('button', { class: 'primary', type: 'submit' }, icon('share', { cls: 'sm' }), 'Share');
  const form = h(
    'form',
    {
      onsubmit: async (e) => {
        e.preventDefault();
        out.replaceChildren();
        const p = people.find((u) => u.id === select.value);
        if (!p) {
          select.setAttribute('aria-invalid', 'true');
          return out.append(errorBox({ message: 'Choose who to share with.' }));
        }
        select.removeAttribute('aria-invalid');
        const mins = expiry.value === 'custom' ? Number(minutes.value) : Number(expiry.value);
        await withBusy(btn, async () => {
          try {
            const pk = await get(`/api/directory/${p.id}/public-key`);
            const own = await get(`/api/documents/${doc.id}/owner-key`);
            const dek = await C.unwrapDek(own.wrappedKey, state.privateKey, true);
            const wrappedKey = await C.wrapDekFor(dek, await C.importPublicKey(pk.publicKey));
            const computed = await C.publicKeyFingerprint(pk.publicKey);
            if (computed !== p.keyFingerprint) throw Object.assign(new Error('The recipient key changed while you were sharing. Reload and try again.'), { code: 'RECIPIENT_KEY_CHANGED' });
            const res = await post(`/api/documents/${doc.id}/grants`, { recipientId: p.id, wrappedKey, recipientKeyFingerprint: computed, expiresInMinutes: mins, maxDownloads: Number(downloads.value) });
            out.replaceChildren(decisionCard(res.decision, { subject: `${doc.filename} shared with ${p.username}` }));
            toast(`Shared with ${p.username}`);
            setTimeout(refresh, 1600);
          } catch (ex) {
            out.replaceChildren(ex.decision ? decisionCard(ex.decision, { subject: `Share of ${doc.filename} with ${p.username}` }) : errorBox(ex));
          }
        });
      },
    },
    field('Recipient', select),
    fpBox,
    h('div', { class: 'row' }, field('Access ends after', expiry), field('Download limit', downloads)),
    minutesField,
    h('p', { class: 'hint', style: 'margin:-6px 0 14px' }, `Policy allows shares of up to ${policy.maxGrantHours} hours and ${policy.maxDownloads} downloads (settings v${policy.settingsVersion}).`),
    btn
  );
  return card({ title: 'Share', icon: 'share', sub: "Your browser re-wraps this file's key for the recipient. The server checks the expiry and limit against policy." }, form, out);
}

function dangerZone(doc) {
  const btn = h('button', { type: 'button', class: 'danger' }, icon('trash', { cls: 'sm' }), 'Delete file');
  btn.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: `Delete ${doc.filename}?`, body: 'The ciphertext and every wrapped key are destroyed and all shares are revoked. This cannot be undone.', confirmLabel: 'Delete permanently', danger: true, icon: 'trash' });
    if (!ok) return;
    await withBusy(btn, async () => {
      try {
        const r = await del(`/api/documents/${doc.id}`, { confirm: true });
        toast(`Deleted ${doc.filename}; ${r.grantsRevoked} share${r.grantsRevoked === 1 ? '' : 's'} revoked`);
        location.hash = '#/documents';
      } catch (e) {
        toast(e.message, { bad: true });
      }
    });
  });
  return card({ title: 'Delete file', cls: 'danger-zone', sub: 'Destroys the encrypted copy and revokes every share.' }, btn);
}
