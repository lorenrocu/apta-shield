<?php

namespace AptaShield\Modules\Hardening;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Core\Plugin;
use AptaShield\Modules\AuditLog\AuditLog;

/**
 * Class Hardening
 * Hardens WordPress configuration and injects security headers.
 */
class Hardening implements ModuleInterface {

    /**
     * Start the module hooks.
     */
    public function run() {
        // Run actions early
        $settings = Plugin::get_instance()->get_settings();

        // 1. File editor check
        if (!empty($settings['hardening_file_edit'])) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        // 2. HTTP Security Headers
        if (!empty($settings['hardening_headers'])) {
            add_filter('wp_headers', [$this, 'inject_security_headers']);
        }

        // 3. XML-RPC Disabler
        if (!empty($settings['hardening_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_action('init', [$this, 'block_xmlrpc_requests'], 1);
        }

        // 4. Hide WordPress Version
        if (!empty($settings['hardening_wp_version'])) {
            add_action('init', [$this, 'remove_wp_version_indicators']);
            add_filter('script_loader_src', [$this, 'remove_version_query_string'], 15);
            add_filter('style_loader_src', [$this, 'remove_version_query_string'], 15);
        }

        // 5. Block Author/User Enumeration
        if (!empty($settings['hardening_author_scan'])) {
            add_action('init', [$this, 'block_author_enumeration'], 1);
        }
    }

    /**
     * Inject Security HTTP Headers.
     *
     * @param array $headers
     * @return array
     */
    public function inject_security_headers($headers) {
        $headers['X-Frame-Options'] = 'SAMEORIGIN';
        $headers['X-Content-Type-Options'] = 'nosniff';
        $headers['X-XSS-Protection'] = '1; mode=block';
        $headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
        return $headers;
    }

    /**
     * Block direct web requests to xmlrpc.php.
     */
    public function block_xmlrpc_requests() {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (strpos($request_uri, 'xmlrpc.php') !== false) {
            AuditLog::log('xmlrpc_blocked', __('Intento de acceso bloqueado a xmlrpc.php.', 'apta-shield'), 0);
            
            status_header(403);
            header('Content-Type: text/plain; charset=utf-8');
            wp_die(
                esc_html__('XML-RPC está desactivado en este sitio por razones de seguridad.', 'apta-shield'),
                esc_html__('Acceso Prohibido - XML-RPC Desactivado', 'apta-shield'),
                ['response' => 403]
            );
        }
    }

    /**
     * Remove WP version hooks from head.
     */
    public function remove_wp_version_indicators() {
        remove_action('wp_head', 'wp_generator');
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
        add_filter('the_generator', '__return_empty_string');
    }

    /**
     * Strip version parameter (?ver=X) from scripts and styles.
     *
     * @param string $src
     * @return string
     */
    public function remove_version_query_string($src) {
        if (strpos($src, 'ver=') !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    /**
     * Block author scans (?author=N) from visitor requests.
     */
    public function block_author_enumeration() {
        if (is_admin()) {
            return;
        }

        $author = isset($_GET['author']) ? sanitize_text_field(wp_unslash($_GET['author'])) : '';
        if ($author !== '' && is_numeric($author)) {
            $author_id = intval($author);
            // translators: %d: ID of the author queried in the URL.
            AuditLog::log('author_scan_blocked', sprintf(__('Intento de enumeración del autor bloqueado (ID consultado: %d).', 'apta-shield'), $author_id), 0);
            
            // Redirect to home url as 301 or 302
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }
}
