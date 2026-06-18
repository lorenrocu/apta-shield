=== Apta Shield ===
Contributors: megapattern, aptasec
Tags: security, firewall, brute force, malware scanner, hardening
Requires at least: 5.8
Tested up to: 7.0
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Premium WordPress security with WAF, brute force block, URL obfuscation, malware scanning, and core reinstallation.

== Description ==

Apta Shield is a comprehensive, lightweight, and robust security engine designed to keep your WordPress site safe from modern threats.

Key Features:
* **Web Application Firewall (WAF)**: Active traffic inspection targeting SQLi, XSS, RCE, and LFI.
* **Brute Force Protection**: Automatic detection and temporary lockout of suspicious IP addresses.
* **URL Obfuscation**: Hide wp-login.php and wp-admin behind a custom secret slug.
* **Security Hardening**: Disable XML-RPC, native code editors, author enumeration, and hide WordPress version.
* **Malware & Integrity Scanner**: Compares local PHP files against official WordPress checksums and scans for heuristic malware signatures.
* **Core Reinstallation**: Reinstall clean core files from WordPress.org in one click if corruption or modifications are found.
* **Audit Log**: Keep track of user activity, login failures, profile updates, and settings modifications.
* **Alert Notifications**: Immediate email alerts for critical security events.

== Installation ==

1. Upload the `apta-shield` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to 'Apta Shield' in the admin side menu to configure the settings.

== Frequently Asked Questions ==

= Does it affect performance? =
No. Apta Shield is built to be extremely lightweight and fast. The WAF rules run efficiently on request startup.

= What happens if I forget my custom login slug? =
You can rename the plugin directory via FTP to disable it, which will restore the default login URL.

== Upgrade Notice ==

= 1.1.0 =
Security and escaping enhancements for WordPress repository compliance.
