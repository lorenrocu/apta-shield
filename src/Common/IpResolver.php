<?php

namespace AptaShield\Common;

defined('ABSPATH') || exit;

/**
 * Class IpResolver
 *
 * Resolves the real client IP address, taking into account trusted reverse
 * proxies so that X-Forwarded-For cannot be spoofed by random clients.
 *
 * Why this matters:
 *   HTTP_X_FORWARDED_FOR is set by the client and is 100% spoofable. If the
 *   firewall relies on it without verifying that the request actually came
 *   from a trusted proxy, an attacker can simply send
 *   "X-Forwarded-For: 1.2.3.4" and bypass any IP-based ban.
 *
 * Strategy:
 *   1. Take REMOTE_ADDR (the actual TCP peer).
 *   2. If REMOTE_ADDR is NOT in the trusted proxy list, use it directly.
 *      XFF is ignored completely. This is the safe default.
 *   3. If REMOTE_ADDR IS a trusted proxy, walk the X-Forwarded-For chain
 *      from right to left and pick the first IP that is not a trusted
 *      proxy. That is the real client.
 *
 * Trusted proxies are stored as an array of IPs or CIDR ranges in the
 * option "apta_shield_trusted_proxies" (e.g. ["127.0.0.1",
 * "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1"]).
 *
 * Typical entries:
 *   - Cloudflare: https://www.cloudflare.com/ips/
 *   - Sucuri:     https://docs.sucuri.net/website-firewall/trueview-headless/ip-addresses/
 *   - Your load balancer internal IP/CIDR
 */
class IpResolver {

    /**
     * Option key used to persist the trusted proxy list.
     */
    private const OPTION_KEY = 'apta_shield_trusted_proxies';

    /**
     * Resolve the real client IP address.
     *
     * @return string Sanitized client IP, or '127.0.0.1' if it cannot be determined.
     */
    public static function get_client_ip() {
        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        if ($remote_addr === '') {
            return '127.0.0.1';
        }

        $trusted_proxies = self::get_trusted_proxies();

        // If REMOTE_ADDR is not a trusted proxy, the connection came from
        // a real client (or an attacker pretending to be one). Either way,
        // XFF cannot be trusted in that case: use REMOTE_ADDR verbatim.
        if (!self::is_trusted_proxy($remote_addr, $trusted_proxies)) {
            return self::normalize($remote_addr);
        }

        // REMOTE_ADDR is a trusted proxy. Walk the XFF chain from right to
        // left and pick the first IP that is not itself a trusted proxy.
        $xff = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])) : '';

        if ($xff === '') {
            return self::normalize($remote_addr);
        }

        $ips = array_map('trim', explode(',', $xff));
        $ips = array_reverse($ips); // walk from closest-to-server to client

        foreach ($ips as $ip) {
            if ($ip === '' || !self::is_valid_ip($ip)) {
                continue;
            }
            if (!self::is_trusted_proxy($ip, $trusted_proxies)) {
                return self::normalize($ip);
            }
        }

        // XFF was full of trusted proxies (or invalid). Fall back to REMOTE_ADDR.
        return self::normalize($remote_addr);
    }

    /**
     * Get the list of trusted proxies from the database.
     *
     * @return array<int,string>
     */
    public static function get_trusted_proxies() {
        $proxies = get_option(self::OPTION_KEY, []);
        if (!is_array($proxies)) {
            return [];
        }
        // Filter out empty / non-string entries, trim each value.
        $proxies = array_filter(array_map('trim', $proxies), function ($v) {
            return is_string($v) && $v !== '';
        });
        return array_values($proxies);
    }

    /**
     * Update the trusted proxy list.
     *
     * Accepts an array of strings, each one either a single IP or a CIDR.
     * Invalid entries are dropped silently.
     *
     * @param array $proxies
     * @return array The cleaned list that was actually persisted.
     */
    public static function set_trusted_proxies($proxies) {
        if (!is_array($proxies)) {
            $proxies = [];
        }

        $clean = [];
        foreach ($proxies as $entry) {
            if (!is_string($entry)) {
                continue;
            }
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (!self::is_valid_cidr_or_ip($entry)) {
                continue;
            }
            $clean[] = $entry;
        }

        $clean = array_values(array_unique($clean));
        update_option(self::OPTION_KEY, $clean);
        return $clean;
    }

    /**
     * Test if an IP is within any of the given trusted ranges.
     *
     * @param string $ip
     * @param array $trusted
     * @return bool
     */
    public static function is_trusted_proxy($ip, $trusted) {
        if (!self::is_valid_ip($ip) || !is_array($trusted) || empty($trusted)) {
            return false;
        }

        foreach ($trusted as $cidr) {
            if (self::ip_in_cidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a given IP belongs to a CIDR range (or matches a plain IP).
     *
     * Supports IPv4 and IPv6.
     *
     * @param string $ip
     * @param string $cidr Either "1.2.3.4" or "1.2.3.0/24" or "::1/128"
     * @return bool
     */
    public static function ip_in_cidr($ip, $cidr) {
        if (!self::is_valid_ip($ip) || !is_string($cidr) || $cidr === '') {
            return false;
        }

        if (strpos($cidr, '/') === false) {
            return strtolower($ip) === strtolower($cidr);
        }

        list($subnet, $bits) = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $subnet = trim($subnet);
        if (!self::is_valid_ip($subnet) || $bits < 0) {
            return false;
        }

        $ip_is_v6 = strpos($ip, ':') !== false;
        $subnet_is_v6 = strpos($subnet, ':') !== false;

        if ($ip_is_v6 !== $subnet_is_v6) {
            return false;
        }

        if ($ip_is_v6) {
            return self::ipv6_in_cidr($ip, $subnet, $bits);
        }

        return self::ipv4_in_cidr($ip, $subnet, $bits);
    }

    /**
     * Validate a string as a plain IP or CIDR.
     *
     * @param string $value
     * @return bool
     */
    public static function is_valid_cidr_or_ip($value) {
        if (!is_string($value) || $value === '') {
            return false;
        }
        if (strpos($value, '/') === false) {
            return self::is_valid_ip($value);
        }
        list($ip, $bits) = explode('/', $value, 2);
        if (!self::is_valid_ip($ip)) {
            return false;
        }
        $bits = (int) $bits;
        $is_v6 = strpos($ip, ':') !== false;
        $max = $is_v6 ? 128 : 32;
        return $bits >= 0 && $bits <= $max;
    }

    /**
     * Validate an IP (IPv4 or IPv6).
     *
     * @param string $ip
     * @return bool
     */
    public static function is_valid_ip($ip) {
        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Normalize an IP for storage: lowercase, collapse IPv6 loopback to IPv4.
     *
     * @param string $ip
     * @return string
     */
    public static function normalize($ip) {
        if (!is_string($ip)) {
            return '127.0.0.1';
        }
        $ip = trim($ip);
        if ($ip === '' || !self::is_valid_ip($ip)) {
            return '127.0.0.1';
        }
        // ::1 (IPv6 loopback) is rarely useful in WAF logs; collapse to 127.0.0.1.
        if ($ip === '::1') {
            return '127.0.0.1';
        }
        return sanitize_text_field(strtolower($ip));
    }

    /**
     * IPv4 in CIDR.
     *
     * @param string $ip
     * @param string $subnet
     * @param int $bits
     * @return bool
     */
    private static function ipv4_in_cidr($ip, $subnet, $bits) {
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        if ($bits > 32) {
            return false;
        }
        $mask = -1 << (32 - $bits);
        // Use & with mask on signed long; PHP integers are 64-bit on most
        // platforms, so this works fine for IPv4.
        return ($ip_long & $mask) === ($subnet_long & $mask);
    }

    /**
     * IPv6 in CIDR.
     *
     * @param string $ip
     * @param string $subnet
     * @param int $bits
     * @return bool
     */
    private static function ipv6_in_cidr($ip, $subnet, $bits) {
        $ip_bin = self::ipv6_to_binary($ip);
        $subnet_bin = self::ipv6_to_binary($subnet);
        if ($ip_bin === null || $subnet_bin === null) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        if ($bits > 128) {
            return false;
        }
        return substr($ip_bin, 0, $bits) === substr($subnet_bin, 0, $bits);
    }

    /**
     * Convert an IPv6 string to a 128-character binary string.
     *
     * @param string $ip
     * @return string|null
     */
    private static function ipv6_to_binary($ip) {
        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return null;
        }
        $bin = '';
        for ($i = 0; $i < 16; $i++) {
            $bin .= str_pad(decbin(ord($packed[$i])), 8, '0', STR_PAD_LEFT);
        }
        return $bin;
    }
}
