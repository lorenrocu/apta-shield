<?php

namespace AptaShield\Admin;

defined('ABSPATH') || exit;

use AptaShield\Core\Plugin;
use AptaShield\Common\Database;
use AptaShield\Common\IpResolver;
use AptaShield\Modules\AuditLog\AuditLog;

/**
 * Class Dashboard
 * Controls the WordPress Admin Menu and AJAX endpoints.
 */
class Dashboard {

    /**
     * Plugin instance.
     *
     * @var Plugin
     */
    private $plugin;

    /**
     * Constructor.
     *
     * @param Plugin $plugin
     */
    public function __construct(Plugin $plugin) {
        $this->plugin = $plugin;
    }

    /**
     * Run actions and filters.
     */
    public function run() {
        add_action('admin_menu', [$this, 'add_menu_page']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);

        // Register AJAX endpoints
        add_action('wp_ajax_apta_shield_save_settings', [$this, 'ajax_save_settings']);
        add_action('wp_ajax_apta_shield_get_bans', [$this, 'ajax_get_bans']);
        add_action('wp_ajax_apta_shield_unban_ip', [$this, 'ajax_unban_ip']);
        add_action('wp_ajax_apta_shield_get_audit_logs', [$this, 'ajax_get_audit_logs']);
        add_action('wp_ajax_apta_shield_clear_audit_logs', [$this, 'ajax_clear_audit_logs']);
    }

    /**
     * Add admin menu page.
     */
    public function add_menu_page() {
        add_menu_page(
            __('Apta Shield', 'apta-shield'),
            __('Apta Shield', 'apta-shield'),
            'manage_options',
            'apta-shield',
            [$this, 'render_dashboard'],
            'dashicons-shield',
            80
        );
    }

    /**
     * Enqueue styles and scripts on the plugin's dashboard page.
     *
     * @param string $hook
     */
    public function enqueue_assets($hook) {
        if ($hook !== 'toplevel_page_apta-shield') {
            return;
        }

        // CSS
        wp_enqueue_style(
            'apta-shield-admin-css',
            APTA_SHIELD_URL . 'assets/css/admin.css',
            [],
            APTA_SHIELD_VERSION
        );

        // JS
        wp_enqueue_script(
            'apta-shield-admin-js',
            APTA_SHIELD_URL . 'assets/js/admin.js',
            ['jquery'],
            APTA_SHIELD_VERSION,
            true
        );

        // Localize Script
        wp_localize_script('apta-shield-admin-js', 'aptaShield', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('apta_shield_nonce'),
            'messages' => [
                'saving'       => __('Guardando ajustes...', 'apta-shield'),
                'saved'        => __('Ajustes guardados correctamente.', 'apta-shield'),
                'error'        => __('Ocurrió un error inesperado.', 'apta-shield'),
                'scan_started' => __('Iniciando escaneo...', 'apta-shield'),
                'reinstalling' => __('Iniciando reinstalación del core...', 'apta-shield'),
                'confirm_reinstall' => __('¿Estás seguro de que deseas reinstalar el núcleo de WordPress? Esto reemplazará los archivos del sistema, pero no tocará tus temas, plugins ni base de datos.', 'apta-shield'),
                'confirm_clear_audit' => __('¿Estás seguro de que deseas vaciar todo el registro de actividad? Esta acción es irreversible.', 'apta-shield'),
            ]
        ]);
    }

    /**
     * Render the admin dashboard view.
     */
    public function render_dashboard() {
        $settings = $this->plugin->get_settings();
        
        // Include main template wrapper
        include APTA_SHIELD_PATH . 'views/main.php';
    }

    /**
     * AJAX handler to save plugin settings.
     */
    public function ajax_save_settings() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        $current_settings = $this->plugin->get_settings();

        // Parse inputs safely
        $new_settings = [
            'firewall_enabled'             => isset($_POST['firewall_enabled']) ? (bool)$_POST['firewall_enabled'] : false,
            'brute_force_enabled'          => isset($_POST['brute_force_enabled']) ? (bool)$_POST['brute_force_enabled'] : false,
            'brute_force_max_attempts'     => isset($_POST['brute_force_max_attempts']) ? max(1, intval($_POST['brute_force_max_attempts'])) : 5,
            'brute_force_lockout_duration' => isset($_POST['brute_force_lockout_duration']) ? max(1, intval($_POST['brute_force_lockout_duration'])) : 60,
            'url_obfuscator_enabled'       => isset($_POST['url_obfuscator_enabled']) ? (bool)$_POST['url_obfuscator_enabled'] : false,
            'url_obfuscator_slug'          => isset($_POST['url_obfuscator_slug']) ? sanitize_title(wp_unslash($_POST['url_obfuscator_slug'])) : 'mi-login-secreto',
            'scanner_auto_scan'            => isset($_POST['scanner_auto_scan']) ? (bool)$_POST['scanner_auto_scan'] : false,
            'scanner_auto_recovery'        => isset($_POST['scanner_auto_recovery']) ? (bool)$_POST['scanner_auto_recovery'] : false,
            'notifier_enabled'             => isset($_POST['notifier_enabled']) ? (bool)$_POST['notifier_enabled'] : false,
            'notifier_email'               => isset($_POST['notifier_email']) ? sanitize_email(wp_unslash($_POST['notifier_email'])) : get_option('admin_email'),

            // Hardening options
            'hardening_headers'            => isset($_POST['hardening_headers']) ? (bool)$_POST['hardening_headers'] : false,
            'hardening_file_edit'          => isset($_POST['hardening_file_edit']) ? (bool)$_POST['hardening_file_edit'] : false,
            'hardening_xmlrpc'             => isset($_POST['hardening_xmlrpc']) ? (bool)$_POST['hardening_xmlrpc'] : false,
            'hardening_wp_version'         => isset($_POST['hardening_wp_version']) ? (bool)$_POST['hardening_wp_version'] : false,
            'hardening_author_scan'        => isset($_POST['hardening_author_scan']) ? (bool)$_POST['hardening_author_scan'] : false,
        ];

        // Ensure the slug is not empty or default wp-login/wp-admin
        if ($new_settings['url_obfuscator_enabled'] && empty($new_settings['url_obfuscator_slug'])) {
            wp_send_json_error(__('El slug de acceso personalizado no puede estar vacío.', 'apta-shield'));
        }

        $merged_settings = array_merge($current_settings, $new_settings);

        // Persist trusted proxies separately (they live in their own option).
        $raw_proxies = isset($_POST['trusted_proxies']) ? sanitize_textarea_field(wp_unslash($_POST['trusted_proxies'])) : '';
        $proxy_lines = preg_split('/\r\n|\r|\n|,/', $raw_proxies);
        IpResolver::set_trusted_proxies(is_array($proxy_lines) ? $proxy_lines : []);
        // Reflect the saved list in $merged_settings so the response is consistent.
        $merged_settings['trusted_proxies'] = IpResolver::get_trusted_proxies();

        if (update_option('apta_shield_settings', $merged_settings)) {
            // Re-register rewrite rules if URL obfuscator settings changed
            if ($current_settings['url_obfuscator_enabled'] !== $merged_settings['url_obfuscator_enabled'] ||
                $current_settings['url_obfuscator_slug'] !== $merged_settings['url_obfuscator_slug']) {
                flush_rewrite_rules();
            }
            wp_send_json_success(__('Ajustes guardados correctamente.', 'apta-shield'));
        }

        wp_send_json_success(__('Ajustes verificados (sin cambios).', 'apta-shield'));
    }

    /**
     * AJAX handler to get list of currently banned IPs.
     */
    public function ajax_get_bans() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        global $wpdb;
        $bans_table = Database::get_bans_table();
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $bans = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, ip_address, reason, banned_until, created_at FROM $bans_table WHERE banned_until > %s ORDER BY created_at DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                current_time('mysql')
            ),
            ARRAY_A
        );

        wp_send_json_success($bans);
    }

    /**
     * AJAX handler to unban an IP.
     */
    public function ajax_unban_ip() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        $ban_id = isset($_POST['ban_id']) ? intval($_POST['ban_id']) : 0;
        if (!$ban_id) {
            wp_send_json_error(__('ID de bloqueo inválido.', 'apta-shield'));
        }

        global $wpdb;
        $bans_table = Database::get_bans_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $deleted = $wpdb->delete($bans_table, ['id' => $ban_id], ['%d']);

        if ($deleted) {
            wp_send_json_success(__('IP desbloqueada correctamente.', 'apta-shield'));
        }

        wp_send_json_error(__('No se pudo eliminar el bloqueo o la IP ya estaba desbloqueada.', 'apta-shield'));
    }

    /**
     * AJAX handler to get paginated audit logs.
     */
    public function ajax_get_audit_logs() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        global $wpdb;
        $audit_table = Database::get_audit_table();

        $paged = isset($_POST['paged']) ? max(1, intval($_POST['paged'])) : 1;
        $search = isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '';
        $limit = 20;
        $offset = ($paged - 1) * $limit;

        $search_term = !empty($search) ? '%' . $wpdb->esc_like($search) . '%' : '';

        // Count total matching logs
        if (!empty($search_term)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $total_logs = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $audit_table WHERE username LIKE %s OR details LIKE %s OR action_type LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $search_term,
                    $search_term,
                    $search_term
                )
            );
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $total_logs = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $audit_table" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                )
            );
        }

        // Fetch logs chunk
        if (!empty($search_term)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $logs = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT id, user_id, username, action_type, ip_address, details, created_at FROM $audit_table WHERE username LIKE %s OR details LIKE %s OR action_type LIKE %s ORDER BY created_at DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $search_term,
                    $search_term,
                    $search_term,
                    $limit,
                    $offset
                ),
                ARRAY_A
            );
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $logs = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT id, user_id, username, action_type, ip_address, details, created_at FROM $audit_table ORDER BY created_at DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $limit,
                    $offset
                ),
                ARRAY_A
            );
        }

        $logs = is_array($logs) ? $logs : [];

        // Format dates
        foreach ($logs as &$log) {
            $log['formatted_date'] = mysql2date(get_option('date_format') . ' ' . get_option('time_format'), $log['created_at']);
        }

        wp_send_json_success([
            'logs'         => $logs,
            'total_pages'  => ceil($total_logs / $limit),
            'current_page' => $paged,
            'total_logs'   => intval($total_logs)
        ]);
    }

    /**
     * AJAX handler to clear/purge all audit logs.
     */
    public function ajax_clear_audit_logs() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        global $wpdb;
        $audit_table = Database::get_audit_table();

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $truncated = $wpdb->query("TRUNCATE TABLE $audit_table");

        // Log the action in the fresh table
        AuditLog::log('audit_cleared', __('Historial de auditoría vaciado por el administrador.', 'apta-shield'));

        wp_send_json_success(__('El registro de actividad ha sido vaciado.', 'apta-shield'));
    }
}
