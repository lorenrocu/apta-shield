<?php
// phpcs:ignoreFile
/**
 * Standalone smoke test for AptaShield\Common\IpResolver.
 *
 * This is a development aid: it does not require WordPress to run. It loads
 * the class file, stubs the WordPress functions the class actually touches
 * (sanitize_text_field, get_option, update_option), then runs through a
 * matrix of realistic and adversarial inputs.
 *
 * Run from the project root:
 *   php tests/IpResolverTest.php
 *
 * Exit code 0 on success, 1 on failure.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Run from the command line: php tests/IpResolverTest.php\n");
    exit(1);
}

$project_root = dirname(__DIR__);
require $project_root . '/src/Common/IpResolver.php';

// ------------------------------------------------------------------
// Stub the WP functions the class uses. We don't need a real WP env.
// ------------------------------------------------------------------
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str) {
        $str = (string) $str;
        $str = strip_tags($str);
        $str = preg_replace('/[\r\n\t\0\x0B]/', '', $str);
        return trim($str);
    }
}
if (!function_exists('get_option')) {
    function get_option($key, $default = false) {
        global $__test_options;
        return array_key_exists($key, $__test_options) ? $__test_options[$key] : $default;
    }
}
if (!function_exists('update_option')) {
    function update_option($key, $value) {
        global $__test_options;
        $__test_options[$key] = $value;
        return true;
    }
}
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

global $__test_options;
$__test_options = [];

// ------------------------------------------------------------------
// Test cases.
// ------------------------------------------------------------------
$failures = 0;
$passes   = 0;

function assertSame($expected, $actual, string $label) {
    global $failures, $passes;
    if ($expected === $actual) {
        echo "  PASS  $label\n";
        $passes++;
    } else {
        echo "  FAIL  $label\n";
        echo "        expected: " . var_export($expected, true) . "\n";
        echo "        actual:   " . var_export($actual, true) . "\n";
        $failures++;
    }
}

function set_server(array $server) {
    foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'] as $k) {
        if (array_key_exists($k, $server)) {
            $_SERVER[$k] = $server[$k];
        } else {
            unset($_SERVER[$k]);
        }
    }
}

// ------------------------------------------------------------------
// 1. validate IPs and CIDRs
// ------------------------------------------------------------------
echo "\n[1] is_valid_ip / is_valid_cidr_or_ip\n";

assertSame(true,  \AptaShield\Common\IpResolver::is_valid_ip('192.168.1.1'),               'IPv4 valid');
assertSame(true,  \AptaShield\Common\IpResolver::is_valid_ip('2001:db8::1'),                'IPv6 valid');
assertSame(false, \AptaShield\Common\IpResolver::is_valid_ip('999.999.999.999'),            'IPv4 invalid');
assertSame(false, \AptaShield\Common\IpResolver::is_valid_ip('not-an-ip'),                  'garbage invalid');
assertSame(true,  \AptaShield\Common\IpResolver::is_valid_cidr_or_ip('10.0.0.0/8'),         'CIDR v4 valid');
assertSame(true,  \AptaShield\Common\IpResolver::is_valid_cidr_or_ip('2001:db8::/32'),      'CIDR v6 valid');
assertSame(false, \AptaShield\Common\IpResolver::is_valid_cidr_or_ip('10.0.0.0/64'),         'CIDR v4 invalid bits');
assertSame(false, \AptaShield\Common\IpResolver::is_valid_cidr_or_ip('10.0.0.0/129'),        'CIDR v6 invalid bits');
assertSame(false, \AptaShield\Common\IpResolver::is_valid_cidr_or_ip('garbage'),             'CIDR garbage');

// ------------------------------------------------------------------
// 2. ip_in_cidr
// ------------------------------------------------------------------
echo "\n[2] ip_in_cidr\n";

assertSame(true,  \AptaShield\Common\IpResolver::ip_in_cidr('10.0.0.5',    '10.0.0.0/8'),     'v4 in /8');
assertSame(true,  \AptaShield\Common\IpResolver::ip_in_cidr('10.255.255.5', '10.0.0.0/8'),     'v4 in /8 boundary high');
assertSame(false, \AptaShield\Common\IpResolver::ip_in_cidr('11.0.0.5',    '10.0.0.0/8'),     'v4 outside /8');
assertSame(true,  \AptaShield\Common\IpResolver::ip_in_cidr('192.168.1.42', '192.168.1.0/24'), 'v4 in /24');
assertSame(false, \AptaShield\Common\IpResolver::ip_in_cidr('192.168.2.42', '192.168.1.0/24'), 'v4 outside /24');
assertSame(true,  \AptaShield\Common\IpResolver::ip_in_cidr('1.2.3.4',     '1.2.3.4'),        'v4 exact match');
assertSame(true,  \AptaShield\Common\IpResolver::ip_in_cidr('2001:db8::1', '2001:db8::/32'),  'v6 in /32');
assertSame(false, \AptaShield\Common\IpResolver::ip_in_cidr('2001:db9::1', '2001:db8::/32'),  'v6 outside /32');

// ------------------------------------------------------------------
// 3. The CRITICAL security test: spoofing attempts.
// ------------------------------------------------------------------
echo "\n[3] Anti-spoofing: client tries to fake their IP via XFF\n";

$__test_options = [];
\__reset_test_options: $__test_options = [];
set_server(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4']);

// 3a. No trusted proxy: XFF must be IGNORED. REMOTE_ADDR wins.
assertSame(
    '203.0.113.5',
    \AptaShield\Common\IpResolver::get_client_ip(),
    'no trusted proxy -> XFF ignored, REMOTE_ADDR used'
);

// 3b. Trusted proxy = REMOTE_ADDR. XFF has an UNTRUSTED client IP -> client IP wins.
set_server(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4']);
\AptaShield\Common\IpResolver::set_trusted_proxies(['203.0.113.0/24']);
assertSame(
    '1.2.3.4',
    \AptaShield\Common\IpResolver::get_client_ip(),
    'trusted proxy + single XFF -> real client picked'
);

// 3c. Trusted proxy + chained XFF: "1.1.1.1, 9.9.9.9, 203.0.113.5".
//     Walking right-to-left, 203.0.113.5 is trusted (skip), 9.9.9.9 is not
//     trusted, so 9.9.9.9 should win. (NOT 1.1.1.1 which is what the OLD
//     vulnerable code would have returned.)
set_server(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 9.9.9.9, 203.0.113.5']);
\AptaShield\Common\IpResolver::set_trusted_proxies(['203.0.113.0/24']);
assertSame(
    '9.9.9.9',
    \AptaShield\Common\IpResolver::get_client_ip(),
    'trusted proxy + chained XFF -> rightmost untrusted IP wins'
);

// 3d. Cloudflare scenario: REMOTE_ADDR is a Cloudflare IP, XFF carries
//     "1.1.1.1, 173.245.48.5". The user has Cloudflare ranges in trusted.
//     173.245.48.5 is in Cloudflare range, 1.1.1.1 is not -> 1.1.1.1 wins.
set_server(['REMOTE_ADDR' => '173.245.48.5', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 173.245.48.5']);
\AptaShield\Common\IpResolver::set_trusted_proxies([
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
]);
assertSame(
    '1.1.1.1',
    \AptaShield\Common\IpResolver::get_client_ip(),
    'Cloudflare scenario -> real client picked through chain'
);

// 3e. Garbage XFF: an attacker injects nonsense, must fall back gracefully.
set_server(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => 'not-an-ip, also-not']);
\AptaShield\Common\IpResolver::set_trusted_proxies(['203.0.113.0/24']);
assertSame(
    '203.0.113.5',
    \AptaShield\Common\IpResolver::get_client_ip(),
    'garbage XFF -> fall back to REMOTE_ADDR'
);

// 3f. IPv6: trusted proxy in v6, client in v6.
set_server(['REMOTE_ADDR' => '2001:db8::1', 'HTTP_X_FORWARDED_FOR' => '2001:db8:beef::1']);
\AptaShield\Common\IpResolver::set_trusted_proxies(['2001:db8::/32']);
assertSame(
    '2001:db8:beef::1',
    \AptaShield\Common\IpResolver::get_client_ip(),
    'v6 trusted proxy + v6 client'
);

// ------------------------------------------------------------------
// 4. set_trusted_proxies sanitization
// ------------------------------------------------------------------
echo "\n[4] set_trusted_proxies input sanitization\n";

$__test_options = [];
$saved = \AptaShield\Common\IpResolver::set_trusted_proxies([
    '  10.0.0.0/8  ',    // trim
    '10.0.0.0/8',         // duplicate (after trim) -> dedup
    'garbage',            // invalid -> drop
    '',                   // empty -> drop
    '999.999.999.999/8',  // invalid IP -> drop
    '192.168.1.1',        // valid single IP
    '2001:db8::/32',      // valid v6 CIDR
]);
assertSame(['10.0.0.0/8', '192.168.1.1', '2001:db8::/32'], $saved, 'sanitization trims, dedups, drops invalid');

// ------------------------------------------------------------------
// 5. normalize
// ------------------------------------------------------------------
echo "\n[5] normalize\n";

assertSame('127.0.0.1',         \AptaShield\Common\IpResolver::normalize('::1'),         '::1 -> 127.0.0.1');
assertSame('127.0.0.1',         \AptaShield\Common\IpResolver::normalize('not-an-ip'),  'invalid -> 127.0.0.1');
assertSame('1.2.3.4',           \AptaShield\Common\IpResolver::normalize('1.2.3.4'),    'plain v4 unchanged');
assertSame('2001:db8::1',       \AptaShield\Common\IpResolver::normalize('2001:DB8::1'),'v6 lowercased');

// ------------------------------------------------------------------
// Summary
// ------------------------------------------------------------------
echo "\n";
echo "Passes:   $passes\n";
echo "Failures: $failures\n";
echo "\n";
exit($failures === 0 ? 0 : 1);
