<?php

namespace AptaShield\Modules\Firewall;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Common\Database;
use AptaShield\Common\IpResolver;

/**
 * Class Firewall
 * WAF (Web Application Firewall) engine.
 */
class Firewall implements ModuleInterface {

    /**
     * Start the module.
     */
    public function run() {
        // Handled early during bootstrap, but we register standard hook for reassurance
        add_action('plugins_loaded', [$this, 'inspect_request']);
    }

    /**
     * Early check to block banned IPs.
     */
    public function early_block_check() {
        $ip = IpResolver::get_client_ip();

        if ($this->is_ip_banned($ip)) {
            $this->render_blocked_page($ip, __('Tu dirección IP ha sido bloqueada debido a sospechas de actividad maliciosa.', 'apta-shield'));
        }
    }

    /**
     * Inspect incoming requests for WAF patterns.
     */
    public function inspect_request() {
        // Only run if firewall is enabled
        $settings = get_option('apta_shield_settings', []);
        if (empty($settings['firewall_enabled'])) {
            return;
        }

        // Whitelist AJAX and cron
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }

        // Patterns to check
        $patterns = [
            'sqli' => '/union\s+select|select\s+.*?\s+from|insert\s+into|update\s+.*?\s+set|delete\s+from|drop\s+table/i',
            'xss'  => '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|javascript:|onload=|onerror=|onclick=/i',
            'lfi'  => '/\.\.\/\.\.\/|wp-config\.php|etc\/passwd/i',
            'rce'  => '/system\(|exec\(|passthru\(|shell_exec\(|eval\(/i',
        ];

        // Combine inputs to inspect.
        // We use wp_unslash to inspect raw inputs against regex patterns, but we sanitize them fully before logging.
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- We inspect raw inputs to detect attack patterns prior to blocking.
        $inputs = [
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Inspecting raw REQUEST_URI for attack patterns.
            'URI' => isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '',
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Inspecting raw QUERY_STRING for attack patterns.
            'GET' => isset($_SERVER['QUERY_STRING']) ? wp_unslash($_SERVER['QUERY_STRING']) : ''
        ];
        
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- This is a WAF inspecting all POST requests globally, nonce verification does not apply.
        if (!empty($_POST)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Inspecting raw POST data in WAF.
            $inputs['POST'] = json_encode(wp_unslash($_POST));
        }

        foreach ($inputs as $source => $value) {
            if (empty($value)) continue;

            foreach ($patterns as $type => $pattern) {
                if (preg_match($pattern, $value)) {
                    $ip = IpResolver::get_client_ip();

                    // Log event
                    $this->log_blocked_request($ip, $type, [
                        'source' => $source,
                        'payload' => substr($value, 0, 500)
                    ]);

                    // Trigger block
                    // translators: %s: Attack vector type detected by firewall (e.g. SQLI, XSS, etc.).
                    $this->render_blocked_page($ip, sprintf(__('Tu solicitud ha sido bloqueada por nuestro Firewall (WAF) [Vector: %s].', 'apta-shield'), strtoupper($type)));
                }
            }
        }
    }

    /**
     * Check if an IP is banned in the database.
     *
     * @param string $ip
     * @return bool
     */
    private function is_ip_banned($ip) {
        global $wpdb;
        $bans_table = Database::get_bans_table();

        // Check if database tables exist
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        if ($wpdb->get_var("SHOW TABLES LIKE '$bans_table'") === null) {
            return false;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $ban = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT id FROM $bans_table WHERE ip_address = %s AND banned_until > %s LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $ip,
                current_time('mysql')
            )
        );

        return $ban !== null;
    }

    /**
     * Log the WAF block to the database.
     *
     * @param string $ip
     * @param string $type
     * @param array $payload
     */
    private function log_blocked_request($ip, $type, $payload) {
        global $wpdb;
        $logs_table = Database::get_logs_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $logs_table,
            [
                'event_type' => 'firewall_block',
                'ip_address' => sanitize_text_field($ip),
                'details'    => json_encode([
                    'attack_type' => sanitize_text_field($type),
                    'source'      => sanitize_text_field($payload['source']),
                    'payload'     => sanitize_text_field($payload['payload'])
                ]),
                'created_at' => current_time('mysql')
            ],
            ['%s', '%s', '%s', '%s']
        );
    }

    /**
     * Render the 403 Forbidden blocked page with custom branding.
     *
     * @param string $ip
     * @param string $message
     */
    private function render_blocked_page($ip, $message) {
        status_header(403);
        
        $html = '<!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Acceso Denegado - Apta Shield</title>
        </head>
        <body style="background-color: #0b0f19; color: #f3f4f6; font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0;">
            <div style="background-color: #151d30; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 40px; max-width: 500px; text-align: center; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);">
                <h1 style="color: #ef4444; font-size: 24px; margin-bottom: 16px; margin-top: 0;">Acceso Denegado (403)</h1>
                <p style="color: #9ca3af; font-size: 15px; line-height: 1.6;">' . esc_html($message) . '</p>
                <div style="margin-top: 24px; background-color: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; font-size: 13px;">
                    Dirección IP: <code style="color: #3b82f6;">' . esc_html($ip) . '</code><br>
                    Firewall: <code style="color: #3b82f6;">Apta Shield Active Engine</code>
                </div>
            </div>
        </body>
        </html>';

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Rendering complete static HTML document.
        echo $html;
        exit;
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
