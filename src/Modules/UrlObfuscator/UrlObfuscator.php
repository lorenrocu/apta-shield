<?php

namespace AptaShield\Modules\UrlObfuscator;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Core\Plugin;

/**
 * Class UrlObfuscator
 *
 * Hides the default WordPress entry points (wp-admin, wp-login.php and
 * wp-register.php) behind a configurable secret slug. The slug is the
 * ONLY way to reach the login form: it serves the form itself by
 * loading wp-login.php internally, with the form's `action` rewritten
 * to point back at the slug. That way the real /wp-login.php URL is
 * never used during a visitor session and can be safely blocked.
 *
 * Behaviour:
 *   - Unauthenticated user visits /{secret-slug}
 *       -> wp-login.php is loaded internally; the login form is
 *          rendered with its action rewritten to the slug. All WP
 *          flows (login POST, logout, lost password, register) work
 *          through the slug.
 *   - Unauthenticated user visits wp-login.php, wp-admin/* or
 *     wp-register.php directly
 *       -> A 404 is rendered. Exceptions: admin-ajax.php and
 *          admin-post.php, which WordPress needs to handle AJAX and
 *          public form posts.
 *   - Authenticated users bypass the gate entirely.
 */
class UrlObfuscator implements ModuleInterface {

    /**
     * Wire up the module hooks.
     */
    public function run() {
        add_action('init', [$this, 'gate_protected_urls'], 1);
        add_action('init', [$this, 'handle_secret_slug'], 2);
    }

    /**
     * Block access to wp-login.php, wp-admin/* and wp-register.php
     * for users who are not logged in.
     */
    public function gate_protected_urls() {
        $settings = Plugin::get_instance()->get_settings();

        if (empty($settings['url_obfuscator_enabled']) || empty($settings['url_obfuscator_slug'])) {
            return;
        }

        // Whitelist background paths that WordPress needs to work.
        if ((defined('DOING_AJAX') && DOING_AJAX)
            || (defined('DOING_CRON') && DOING_CRON)
            || (defined('REST_REQUEST') && REST_REQUEST)) {
            return;
        }

        $request_path = $this->get_request_path();
        if ($request_path === '') {
            return;
        }

        // The secret slug is handled separately by handle_secret_slug().
        $secret_slug = trim($settings['url_obfuscator_slug'], '/');
        if ($request_path === $secret_slug) {
            return;
        }

        if (!$this->is_protected_path($request_path)) {
            return;
        }

        // Logged-in users go through normally.
        if (is_user_logged_in()) {
            return;
        }

        // Whitelist WP's own internal admin endpoints that must stay
        // reachable even for unauthenticated visitors (AJAX, public
        // form posts).
        if ($this->is_internal_admin_endpoint($request_path)) {
            return;
        }

        $this->render_404();
    }

    /**
     * Serve the login page at the configured secret slug.
     *
     * wp-login.php is loaded directly so the form, its assets and all
     * WP login hooks (2FA, captcha, lost password, register, logout)
     * keep working. The form's `action` attribute and any other
     * internal link to wp-login.php are rewritten to point at the
     * slug, so the real wp-login.php URL is never used.
     */
    public function handle_secret_slug() {
        $settings = Plugin::get_instance()->get_settings();

        if (empty($settings['url_obfuscator_enabled']) || empty($settings['url_obfuscator_slug'])) {
            return;
        }

        $request_path = $this->get_request_path();
        $secret_slug = trim($settings['url_obfuscator_slug'], '/');

        if ($request_path !== $secret_slug) {
            return;
        }

        // Already logged in: jump to the admin unless the visitor is
        // explicitly asking to log out (so they can use the slug to
        // log out without first being redirected to the dashboard).
        if (is_user_logged_in()) {
            $action = isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if ($action !== 'logout') {
                wp_safe_redirect(admin_url());
                exit;
            }
        }

        // Pre-initialize the globals that wp-login.php's form-render
        // path references but only sets under specific branches
        // (POST submit, password-reset cookie, register/lostpassword
        // action). Without this, the first GET to the slug would emit
        // PHP 8.x "undefined variable" notices on $user_login and
        // $error (which are then captured by our output buffer and
        // surfaced in the rendered HTML).
        $predef_globals = [
            'user_login'      => '',
            'user_email'      => '',
            'error'           => '',
            'redirect_to'     => '',
            'interim_login'   => false,
            'rp_login'        => '',
            'rp_key'          => '',
            'customize_login' => false,
            'secure_cookie'   => '',
            'reauth'          => false,
        ];
        foreach ($predef_globals as $name => $default) {
            if (!isset($GLOBALS[$name])) {
                $GLOBALS[$name] = $default;
            }
        }

        // Declare local references to the global variables. Since wp-login.php is required
        // inside this method, it executes within this method's scope. Declaring these local
        // variables as references to the globals ensures they are defined in this scope
        // (preventing PHP 8.x undefined variable warnings) while keeping them fully synced
        // with the global scope.
        $user_login      = & $GLOBALS['user_login'];
        $user_email      = & $GLOBALS['user_email'];
        $error           = & $GLOBALS['error'];
        $redirect_to     = & $GLOBALS['redirect_to'];
        $interim_login   = & $GLOBALS['interim_login'];
        $rp_login        = & $GLOBALS['rp_login'];
        $rp_key          = & $GLOBALS['rp_key'];
        $customize_login = & $GLOBALS['customize_login'];
        $secure_cookie   = & $GLOBALS['secure_cookie'];
        $reauth          = & $GLOBALS['reauth'];

        // Trick wp-login.php into thinking it was loaded directly so
        // its own self-references resolve to the real wp-login.php
        // path before we rewrite them in the output buffer below.
        $_SERVER['SCRIPT_NAME'] = '/wp-login.php';
        $_SERVER['PHP_SELF']     = '/wp-login.php';
        if (!empty($_SERVER['QUERY_STRING'])) {
            $_SERVER['REQUEST_URI'] = '/wp-login.php?' . $_SERVER['QUERY_STRING'];
        } else {
            $_SERVER['REQUEST_URI'] = '/wp-login.php';
        }

        // Capture wp-login.php's output so we can rewrite the form
        // action and any other internal links to point at the slug.
        ob_start();
        require_once ABSPATH . 'wp-login.php';
        $html = ob_get_clean();

        // wp-login.php exits on its own when it sends a redirect or
        // dies with an error - in those cases the buffer is empty
        // and there's nothing to rewrite.
        if ($html === '' || $html === false) {
            exit;
        }

        // Rewrite all references to wp-login.php in the rendered HTML
        // to point at our secret slug instead. We use a regex so we
        // match absolute, protocol-relative, and path-relative URLs
        // (and any query string), and we preserve the rest of the
        // path so it still works if WordPress is installed in a
        // subdirectory.
        $html = preg_replace_callback(
            '#(https?:)?//[^"\'<>\s]*?/wp-login\.php#i',
            function ($matches) use ($secret_slug) {
                return str_replace('/wp-login.php', '/' . $secret_slug, $matches[0]);
            },
            $html
        );
        $html = preg_replace(
            '#(["\'])/wp-login\.php#i',
            '$1/' . $secret_slug,
            $html
        );

        echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Already escaped by wp-login.php / WP core.
        exit;
    }

    /**
     * Whether the path targets a WordPress endpoint we want to hide.
     */
    private function is_protected_path($path) {
        if ($path === 'wp-admin' || strpos($path, 'wp-admin/') === 0) {
            return true;
        }
        if ($path === 'wp-login.php' || strpos($path, 'wp-login.php/') === 0) {
            return true;
        }
        if ($path === 'wp-register.php' || strpos($path, 'wp-register.php/') === 0) {
            return true;
        }
        return false;
    }

    /**
     * WP-internal admin endpoints that must stay reachable even for
     * unauthenticated visitors (AJAX requests and public form posts).
     */
    private function is_internal_admin_endpoint($path) {
        $whitelist = [
            'admin-ajax.php',
            'admin-post.php',
        ];
        foreach ($whitelist as $endpoint) {
            if ($path === 'wp-admin/' . $endpoint) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract the request path, removing any subdirectory prefix in
     * which WordPress itself is installed.
     */
    private function get_request_path() {
        $raw = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $path = trim(wp_parse_url($raw, PHP_URL_PATH), '/');

        $site_path = trim(wp_parse_url(home_url(), PHP_URL_PATH), '/');
        if (!empty($site_path) && strpos($path, $site_path) === 0) {
            $path = trim(substr($path, strlen($site_path)), '/');
        }
        return $path;
    }

    /**
     * Render the active theme's 404 template (or a plain wp_die fallback).
     */
    private function render_404() {
        status_header(404);
        nocache_headers();

        global $wp_query;
        if (is_object($wp_query)) {
            $wp_query->set_404();
        }

        $template = get_query_template('404');
        if ($template) {
            include $template;
        } else {
            wp_die(
                '<h1>Página no encontrada</h1><p>El enlace que has seguido no existe o ha cambiado.</p>',
                '404 Not Found',
                ['response' => 404]
            );
        }
        exit;
    }
}
