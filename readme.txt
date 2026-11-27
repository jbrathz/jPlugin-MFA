=== jPlugin-MFA ===
Contributors: jirath
Tags: two-factor, 2fa, totp, authenticator, login-security
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Two-factor authentication (TOTP) for the native WordPress login. Google Authenticator or any TOTP app. Standalone: WordPress core only, no other plugin.

== Description ==

jPlugin-MFA adds a second step to the normal WordPress login form (`wp-login.php`).
After the password is accepted, the user must enter a 6 digit code from an
authenticator app (Google Authenticator, Microsoft Authenticator, Authy,
1Password, Bitwarden, Aegis, 2FAS, ...).

**Scope**

* Only the native WordPress login. The login screens of other plugins
  (`jPlugin-Member`, `jPlugin-Elearning`, WooCommerce, ...) are not touched,
  filtered or modified in any way.
* No dependency: no composer package, no external service, no shared code with
  any other plugin.

**Features**

* Standard TOTP: RFC 6238, SHA-1, 6 digits, 30 seconds, `otpauth://` URI, so any
  authenticator app works.
* QR code generated locally in the browser from the `otpauth://` URI; the secret
  is never sent to a third party. A manual key is also shown.
* 10 single use recovery codes, stored only as keyed hashes.
* Forced enrolment: in "required" mode an in-scope user is taken straight to the
  enrolment screen after the password, so nobody can be locked out before
  finishing setup.
* Replay protection (a code can never be used twice) and a configurable ± time
  window for clock drift.
* Wrong code lockout: after N failures the pending login is dropped and the
  password must be entered again.
* Audit log with hashed IP / user agent only, pruned automatically after the
  configured retention (90 days by default), and a one click CSV report.
* Application Passwords and XML-RPC are blocked for users who must use 2FA
  (switchable for Application Passwords).

**Privacy**

* Client IP and user agent are stored only as salted hashes.
* TOTP secrets are encrypted at rest with `sodium_crypto_secretbox`
  (AES-256-GCM fallback). The key is derived from the site salts or from an
  optional `JMFA_KEY` constant.
* No data is sent anywhere.

== Installation ==

1. Upload the `jPlugin-MFA` folder to `wp-content/plugins/`.
2. Activate the plugin. Activation only creates two tables and an "off" setting,
   so the site keeps working exactly as before.
3. Go to **jPlugin-MFA → การตั้งค่า**, choose "บังคับ" (required) and the roles to
   protect, then save.
4. Open **jPlugin-MFA → ความปลอดภัยของฉัน** and enrol an authenticator app.
   Keep the recovery codes somewhere safe.

== Frequently Asked Questions ==

= Does deactivating the plugin lock anyone out? =

No. Deactivation only drops half finished logins; secrets, recovery codes,
settings and the audit log are kept. With the plugin off everybody logs in with
the password only. Re-activating restores the previous state.

= I lost my phone and have no recovery codes =

Another administrator can use **jPlugin-MFA → ผู้ใช้ → รีเซ็ต MFA**.
Without a second administrator, add this line to `wp-config.php`, log in, then
remove it:

`define( 'JMFA_DISABLE', true );`

or with WP-CLI: `wp jmfa reset <username>`.

= Do other plugins' logins require a code? =

No. Only `wp-login.php`. Member systems that use their own session (for example
`jPlugin-Member`) are untouched.

= What happens if AUTH_KEY is rotated? =

Stored secrets become unreadable. Affected users are told to ask an
administrator for a reset; nothing else breaks. Define `JMFA_KEY` to keep the
encryption key independent from the salts.

= How long are the logs kept? =

90 days by default, configurable between 7 and 3650 days. Deletion happens in
two places so the window is a guarantee, not a best effort: the daily
`jmfa_prune` cron event and an inline check that runs at most every six hours
(which covers hosts where WP-Cron is disabled or the site gets little traffic).

= Can I export the audit log? =

Yes. **jPlugin-MFA → บันทึกเหตุการณ์** has a CSV export with 7 / 30 / 90 day or
"everything kept" ranges. The file is generated on the fly (never written to
disk), uses a UTF-8 BOM so Excel shows Thai correctly, and neutralises
spreadsheet formula injection. IP addresses and user agents appear only as
hashes.

== Changelog ==

= 1.0.0 =
* First release: TOTP, recovery codes, forced enrolment, lockout, audit log,
  admin screens, WP-CLI, break glass switch.