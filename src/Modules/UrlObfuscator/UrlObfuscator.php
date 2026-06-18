<?php

namespace AptaShield\Modules\UrlObfuscator;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Core\Plugin;
use AptaShield\Common\IpResolver;

/**
 * Class UrlObfuscator
 * Obfuscates wp-login.php and wp-admin, replacing them with a custom slug.
 */
class UrlObfuscator implements ModuleInterface {

    /**
     * Cookie name for validation.
     */
    private $cookie_name = 'apta_shield_auth';

    /**
     * Start the module.
     */
    public function run() {
        add_action('init', [$this, 'handle_secret_slug_redirect'], 1);
        add_action('login_init', [$this, 'block_wp_login_direct_access'], 1);
        add_action('wp_logout', [$this, 'clear_auth_cookie']);
    }

    /**
     * Check if request matches the secret slug.
     */
    public function handle_secret_slug_redirect() {
        $settings = Plugin::get_instance()->get_settings();
        
        if (empty($settings['url_obfuscator_enabled']) || empty($settings['url_obfuscator_slug'])) {
            return;
        }

        // Get requested URI path
        $raw_request_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $request_path = trim(wp_parse_url($raw_request_uri, PHP_URL_PATH), '/');
        
        // Strip subdirectory if WordPress is installed in a subdirectory
        $site_path = trim(wp_parse_url(home_url(), PHP_URL_PATH), '/');
        if (!empty($site_path)) {
            if (strpos($request_path, $site_path) === 0) {
                $request_path = trim(substr($request_path, strlen($site_path)), '/');
            }
        }

        $secret_slug = trim($settings['url_obfuscator_slug'], '/');

        // Check if the requested path is exactly our secret slug
        if ($request_path === $secret_slug) {
            $this->set_auth_cookie();
            
            // Redirect to wp-login.php with query string parameters if any
            $redirect_url = site_url('wp-login.php');
            if (!empty($_SERVER['QUERY_STRING'])) {
                $query_params = [];
                wp_parse_str(wp_unslash($_SERVER['QUERY_STRING']), $query_params);
                // Sanitize keys and values safely
                $sanitized_params = [];
                foreach ($query_params as $key => $value) {
                    $sanitized_key = sanitize_key($key);
                    if (is_array($value)) {
                        $sanitized_params[$sanitized_key] = array_map('sanitize_text_field', $value);
                    } else {
                        $sanitized_params[$sanitized_key] = sanitize_text_field($value);
                    }
                }
                $redirect_url = add_query_arg($sanitized_params, $redirect_url);
            }
            
            wp_safe_redirect($redirect_url);
            exit;
        }
    }

    /**
     * Block direct access to wp-login.php and wp-register.php if auth cookie is not set.
     */
    public function block_wp_login_direct_access() {
        $settings = Plugin::get_instance()->get_settings();

        if (empty($settings['url_obfuscator_enabled'])) {
            return;
        }

        // Whitelist AJAX and cron
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }

        // If the user is already logged in as admin or has active user session, let them pass
        if (is_user_logged_in() && current_user_can('read')) {
            return;
        }

        // Check if the cookie is set and has the correct value
        if ($this->verify_auth_cookie()) {
            return;
        }

        // Check if it is a logout action - allow it
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['action']) && $_GET['action'] === 'logout') { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            return;
        }

        // Block request and render 404
        $this->render_404();
    }

    /**
     * Set authorization cookie.
     */
    private function set_auth_cookie() {
        $value = $this->generate_cookie_hash();
        // Valid for 1 hour
        setcookie($this->cookie_name, $value, time() + 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        if (SITECOOKIEPATH !== COOKIEPATH) {
            setcookie($this->cookie_name, $value, time() + 3600, SITECOOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        }
    }

    /**
     * Clear authorization cookie.
     */
    public function clear_auth_cookie() {
        setcookie($this->cookie_name, '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        if (SITECOOKIEPATH !== COOKIEPATH) {
            setcookie($this->cookie_name, '', time() - 3600, SITECOOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        }
    }

    /**
     * Verify the authorization cookie.
     *
     * @return bool
     */
    private function verify_auth_cookie() {
        $cookie_val = isset($_COOKIE[$this->cookie_name]) ? sanitize_text_field(wp_unslash($_COOKIE[$this->cookie_name])) : '';
        if ($cookie_val === '') {
            return false;
        }

        $expected = $this->generate_cookie_hash();
        return hash_equals($expected, $cookie_val);
    }

    /**
     * Generate unique secure cookie hash based on user IP and site salts.
     *
     * @return string
     */
    private function generate_cookie_hash() {
        $ip = IpResolver::get_client_ip();
        $salt = defined('AUTH_KEY') ? AUTH_KEY : 'apta_fallback_salt_key';
        return hash_hmac('sha256', $ip . '_apta_auth', $salt);
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

    /**
     * Render WordPress 404 page.
     */
    private function render_404() {
        status_header(404);
        nocache_headers();

        global $wp_query;
        if (is_object($wp_query)) {
            $wp_query->set_404();
        }

        // Load 404 template from the active theme
        $template = get_query_template('404');
        if ($template) {
            include $template;
        } else {
            // Fallback plain 404
            wp_die(
                '<h1>Página no encontrada</h1><p>El enlace que has seguido no existe o ha cambiado.</p>',
                '404 Not Found',
                ['response' => 404]
            );
        }
        exit;
    }
}
