import { h, icon, field, passwordInput, errorBox, alertBox, fingerprint, withBusy } from '../ui.js';
import { signIn, unlock, startEnrollment, completeEnrollment, state, signOut } from '../vault.js';

function layout(card) {
  return h(
    'div',
    { class: 'auth' },
    h(
      'aside',
      { class: 'auth-aside' },
      h('a', { class: 'brand', href: '#/', 'aria-label': 'VaultShare' }, h('span', { class: 'brand-mark' }, icon('shield')), h('span', { class: 'brand-name' }, 'VaultShare')),
      h(
        'div',
        {},
        h('h1', {}, 'Share confidential files without handing over the keys.'),
        h('p', { class: 'lead' }, 'Files are encrypted in your browser before upload. Only the people you choose can open them, for as long as you allow.'),
        h(
          'ul',
          { class: 'feature-list' },
          [
            ['lock', 'AES-256-GCM encryption in the browser; the server stores only ciphertext'],
            ['clock', 'Shares that expire, have download limits and can be revoked at any time'],
            ['droplet', 'Every opened copy carries a signed, traceable watermark'],
            ['audit', 'A hash-chained audit trail that reveals any tampering'],
          ].map(([ic, t]) => h('li', {}, icon(ic), h('span', {}, t)))
        )
      ),
      h('p', { class: 'foot' }, 'Runs locally. Your password never leaves this device.')
    ),
    h('main', { class: 'auth-main' }, h('div', { class: 'auth-card' }, card))
  );
}

export function renderSignIn(root, { onDone, message }) {
  const user = h('input', { name: 'username', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
  const pw = passwordInput({ name: 'password', autocomplete: 'current-password', required: true });
  const err = h('div', { 'aria-live': 'assertive' });
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Sign in');
  const form = h(
    'form',
    {
      novalidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        err.replaceChildren();
        user.removeAttribute('aria-invalid');
        pw.input.removeAttribute('aria-invalid');
        if (!user.value.trim() || !pw.input.value) {
          if (!user.value.trim()) user.setAttribute('aria-invalid', 'true');
          if (!pw.input.value) pw.input.setAttribute('aria-invalid', 'true');
          return err.append(errorBox({ message: 'Enter your username and password.' }));
        }
        await withBusy(btn, async () => {
          try {
            await signIn(user.value.trim().toLowerCase(), pw.input.value);
            pw.input.value = '';
            onDone();
          } catch (ex) {
            err.append(errorBox(ex.code ? ex : { message: 'Your key could not be opened with this password.' }));
          }
        });
      },
    },
    h('h2', {}, 'Welcome back'),
    h('p', { class: 'lead' }, 'Sign in to open your vault. Your password unlocks your private key on this device.'),
    message ? alertBox('warning', null, message) : null,
    err,
    field('Username', user),
    field('Password', pw.wrap),
    btn,
    h('p', { class: 'switch' }, 'Have an enrollment code? ', h('a', { href: '#/enroll' }, 'Set up your account'))
  );
  root.replaceChildren(layout(form));
  user.focus();
}

export function renderUnlock(root, { onDone }) {
  const pw = passwordInput({ autocomplete: 'current-password', required: true });
  const err = h('div', { 'aria-live': 'assertive' });
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Unlock');
  const form = h(
    'form',
    {
      onsubmit: async (e) => {
        e.preventDefault();
        err.replaceChildren();
        await withBusy(btn, async () => {
          try {
            await unlock(pw.input.value);
            onDone();
          } catch (ex) {
            err.append(errorBox(ex));
          }
        });
      },
    },
    h('h2', {}, `Unlock your key`),
    h('p', { class: 'lead' }, `You are still signed in as ${state.user.username}. Your private key is cleared from memory whenever the page reloads.`),
    err,
    field('Password', pw.wrap),
    btn,
    h(
      'p',
      { class: 'switch' },
      h(
        'a',
        {
          href: '#/',
          onclick: async (e) => {
            e.preventDefault();
            await signOut();
            location.reload();
          },
        },
        'Sign out instead'
      )
    )
  );
  root.replaceChildren(layout(form));
  pw.input.focus();
}

export function renderEnroll(root, { onDone }) {
  const user = h('input', { autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
  const code = h('input', { autocomplete: 'one-time-code', placeholder: 'XXXX-XXXX-XXXX-XXXX', spellcheck: 'false', required: true, style: 'font-family:var(--mono);letter-spacing:0.04em' });
  const pw = passwordInput({ autocomplete: 'new-password', required: true, minlength: '10' });
  const pw2 = passwordInput({ autocomplete: 'new-password', required: true });
  const err = h('div', { 'aria-live': 'assertive' });
  const steps = h('ol', { class: 'steps', hidden: true, 'aria-live': 'polite' });
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Create my key');
  const STEP_TEXT = { derive: 'Deriving keys from your password', keypair: 'Generating your RSA key pair', register: 'Registering your public key' };
  const renderSteps = (current, failed = false) => {
    const keys = Object.keys(STEP_TEXT);
    const i = current === 'all' ? keys.length : keys.indexOf(current);
    steps.replaceChildren(...keys.map((k, j) => h('li', { class: j < i ? 'done' : j === i ? (failed ? 'fail' : 'run') : '' }, h('span', { class: 's-dot' }, icon('check')), STEP_TEXT[k])));
  };

  const form = h(
    'form',
    {
      novalidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        err.replaceChildren();
        const problems = [];
        if (!/^[a-z][a-z0-9._-]{2,31}$/.test(user.value.trim().toLowerCase())) problems.push({ field: 'Username', message: 'must be 3–32 lowercase letters or digits, starting with a letter' });
        if (code.value.trim().length < 16) problems.push({ field: 'Enrollment code', message: 'looks incomplete' });
        if (pw.input.value.length < 10) problems.push({ field: 'Password', message: 'must be at least 10 characters' });
        if (pw.input.value !== pw2.input.value) problems.push({ field: 'Confirmation', message: 'does not match the password' });
        if (problems.length) return err.append(errorBox({ message: 'Fix these before continuing.', details: problems }));
        steps.hidden = false;
        let current = 'derive';
        await withBusy(btn, async () => {
          try {
            const uname = user.value.trim().toLowerCase();
            renderSteps('derive');
            const start = await startEnrollment(uname, code.value.trim());
            await completeEnrollment(uname, code.value.trim(), pw.input.value, start, (k) => renderSteps((current = k)));
            renderSteps('all');
            pw.input.value = pw2.input.value = '';
            form.replaceChildren(
              h('div', { class: 'e-icon', style: 'width:48px;height:48px;border-radius:14px;background:var(--success-soft);color:var(--success);display:grid;place-items:center;margin-bottom:16px' }, icon('check-circle', { cls: 'lg' })),
              h('h2', {}, 'Your key is ready'),
              h('p', { class: 'lead' }, 'This is your public-key fingerprint. People who share files with you can compare it with what their screen shows.'),
              fingerprint(state.user.keyFingerprint, { copy: true }),
              h('div', { style: 'margin-top:20px' }, alertBox('warning', 'There is no password recovery', 'If you forget your password, an administrator can issue a new key, but files shared with your old key cannot be opened again.')),
              h('button', { class: 'primary', type: 'button', style: 'margin-top:20px', onclick: onDone }, 'Continue to VaultShare')
            );
          } catch (ex) {
            renderSteps(current, true);
            err.append(errorBox(ex));
          }
        });
      },
    },
    h('h2', {}, 'Set up your account'),
    h('p', { class: 'lead' }, 'Use the one-time code from your administrator. Your browser creates a key pair and locks the private half with your password.'),
    err,
    field('Username', user),
    field('Enrollment code', code),
    field('New password', pw.wrap, 'At least 10 characters. A passphrase of several words works well.'),
    field('Confirm password', pw2.wrap),
    btn,
    steps,
    h('p', { class: 'switch' }, 'Already set up? ', h('a', { href: '#/' }, 'Sign in'))
  );
  root.replaceChildren(layout(form));
  user.focus();
}
