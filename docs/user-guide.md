# User guide (operators and viewers)

## Roles

- **Operator** — upload files, share them with time-limited access, revoke access, delete files, open files shared with you.
- **Viewer** — open files shared with you. Viewers cannot upload or re-share.

## First sign-in: set up your account

Your administrator gives you a username and a one-time **enrollment code** (`XXXX-XXXX-XXXX-XXXX`).

1. On the sign-in screen choose **Set up your account**.
2. Enter the username, the code and a password of at least 10 characters (a passphrase of several words works well).
3. Choose **Create my key**. Your browser derives keys from the password, creates an RSA key pair, locks the private key with your password and registers only the public key.
4. Note your **key fingerprint**. People who share with you can compare it.

There is **no password recovery**. If you forget your password, an administrator can issue a new code, but files shared with your old key cannot be opened again until their owners share them again.

## Signing in and unlocking

Sign in with your username and password. The password never leaves your browser; it opens your private key locally. If you reload the page, you stay signed in but your key is cleared from memory — enter your password on the **Unlock** screen. Sessions end after 30 minutes without activity.

## Uploading (operators)

1. Choose **Upload** and pick or drop a file: `.txt`, `.md`, `.csv`, `.pdf`, `.png` or `.jpg` up to 10 MB (your administrator may change these).
2. The progress list shows each step: content check, encryption, key wrapping, upload.
3. The **verdict slip** shows the result, its **severity** and **what to do next**. *Allowed* means the server accepted the sealed copy. *Rejected* names the rule, for example `CONTENT_TYPE_MISMATCH`: "The file is named .pdf but its contents are plain text, not a PDF." Rejected uploads are kept in **My decisions** so you can compare them with accepted ones.

## Sharing (operators)

1. Open the file and use the **Share** panel.
2. Choose the recipient. Compare the **key fingerprint** shown with what the recipient sees on their Account page before sharing anything sensitive.
3. Choose when access ends (1 minute to 7 days, or custom) and the download limit.
4. Choose **Share**. If a rule refuses the share — for example the expiry is longer than policy allows — the verdict slip says which rule and what the limits are.

Under **Who has access** you can see each share's status (*Active*, *Expired*, *No downloads left*, *Revoked*, *Key changed*) and **Revoke** it. Revocation takes effect on the recipient's next attempt; copies they already saved remain watermarked to them.

**Delete file** destroys the encrypted copy and every wrapped key and revokes every share. It cannot be undone.

## Opening a file

Choose **Open and download**. The server checks your access and records a decision. If allowed, your browser decrypts the file, verifies it has not been altered, adds a watermark with your name, the time and a reference, and shows a preview with **Save**.

If access is refused, the verdict slip names the reason:

| Rule | What it means | What to do |
|---|---|---|
| `GRANT_EXPIRED` | The share's time ran out | Ask the owner to share again |
| `GRANT_REVOKED` | The owner or an administrator revoked it | Contact the owner |
| `DOWNLOAD_LIMIT_REACHED` | All downloads were used | Ask the owner for a new share |
| `KEY_MISMATCH` | Your key was reset after the share was made | Ask the owner to revoke and share again |
| `INTEGRITY_CHECK_FAILED` | The encrypted copy was altered; nothing was decrypted. It is recorded automatically | Report it to your administrator |

## Decision history and reports

**My decisions** lists every allow and deny about your requests, with severity; filter by result, severity or action. Select a row to see the full verdict slip. **Export report (JSON)** or **Export CSV** downloads a sanitised record (no keys, file contents or IP addresses).

## Changing your password

**Account → Change password.** Your private key is re-locked with the new password in your browser, and your other sessions are signed out.
