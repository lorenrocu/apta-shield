<?php

namespace AptaShield\Modules\BruteForce;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Common\Database;
use AptaShield\Common\IpResolver;
use AptaShield\Core\Plugin;

/**
 * Class BruteForce
 * Detects login failures and blocks brute-force attempts.
 */
class BruteForce implements ModuleInterface {

    /**
     * Start the module.
     */
    public function run() {
        add_action('wp_login_failed', [$this, 'handle_login_failure']);
        add_action('xmlrpc_login_error', [$this, 'handle_xmlrpc_failure']);
    }

    /**
     * Handle failed standard login attempts.
     *
     * @param string $username
     */
    public function handle_login_failure($username) {
        $this->record_failure($username, 'wp_login');
    }

    /**
     * Handle failed XML-RPC login attempts.
     *
     * @param string $username
     */
    public function handle_xmlrpc_failure($username) {
        $this->record_failure($username, 'xmlrpc');
    }

    /**
     * Record login failure and block IP if threshold is reached.
     *
     * @param string $username
     * @param string $source
     */
    private function record_failure($username, $source) {
        global $wpdb;
        $ip = IpResolver::get_client_ip();
        $logs_table = Database::get_logs_table();

        // Log the failure
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $logs_table,
            [
                'event_type' => 'login_fail',
                'ip_address' => $ip,
                'username'   => sanitize_user($username),
                'details'    => json_encode(['source' => $source]),
                'created_at' => current_time('mysql')
            ],
            ['%s', '%s', '%s', '%s', '%s']
        );

        // Check if IP should be banned
        $settings = Plugin::get_instance()->get_settings();
        $max_attempts = intval($settings['brute_force_max_attempts']);
        $lockout_duration = intval($settings['brute_force_lockout_duration']); // in minutes

        // Count failures in the last 15 minutes
        $time_limit = wp_date('Y-m-d H:i:s', time() - 900);
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $failures = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM $logs_table WHERE ip_address = %s AND event_type = 'login_fail' AND created_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $ip,
                $time_limit
            )
        );

        if (intval($failures) >= $max_attempts) {
            $this->ban_ip($ip, $lockout_duration);
        }
    }

    /**
     * Ban an IP address.
     *
     * @param string $ip
     * @param int $duration_minutes
     */
    private function ban_ip($ip, $duration_minutes) {
        global $wpdb;
        $bans_table = Database::get_bans_table();
        
        $banned_until = wp_date('Y-m-d H:i:s', time() + ($duration_minutes * 60));

        // Insert or update ban
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->replace(
            $bans_table,
            [
                'ip_address'   => $ip,
                'reason'       => 'brute_force',
                'banned_until' => $banned_until,
                'created_at'   => current_time('mysql')
            ],
            ['%s', '%s', '%s', '%s']
        );

        // Also trigger Notifier if loaded
        $notifier = Plugin::get_instance()->get_module('notifier');
        if ($notifier) {
            $notifier->send_brute_force_alert($ip, $duration_minutes);
        }
    }

    /**
     * @deprecated since 1.1.0. Use AptaShield\Common\IpResolver::get_client_ip() instead.
     *             Kept as a thin wrapper for backward compatibility.
     *
     * @return string
     */
    private function get_user_ip() {
        return IpResolver::get_client_ip();
    }
}
