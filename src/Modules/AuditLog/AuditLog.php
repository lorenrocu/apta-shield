<?php

namespace AptaShield\Modules\AuditLog;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Common\Database;
use AptaShield\Common\IpResolver;

/**
 * Class AuditLog
 * Tracks user activity and site modifications.
 */
class AuditLog implements ModuleInterface {

    /**
     * Start the module hooks.
     */
    public function run() {
        // Session hooks
        add_action('wp_login', [$this, 'log_login_success'], 10, 2);
        add_action('wp_login_failed', [$this, 'log_login_failure'], 10, 1);
        add_action('wp_logout', [$this, 'log_logout'], 10, 0);

        // Content hooks
        add_action('transition_post_status', [$this, 'log_post_transition'], 10, 3);
        add_action('before_delete_post', [$this, 'log_post_deletion'], 10, 1);

        // Plugin & Theme hooks
        add_action('activated_plugin', [$this, 'log_plugin_activation'], 10, 2);
        add_action('deactivated_plugin', [$this, 'log_plugin_deactivation'], 10, 2);
        add_action('switch_theme', [$this, 'log_theme_switch'], 10, 2);

        // User profile hooks
        add_action('user_register', [$this, 'log_user_registration'], 10, 1);
        add_action('delete_user', [$this, 'log_user_deletion'], 10, 1);
        add_action('profile_update', [$this, 'log_profile_update'], 10, 2);

        // Settings hooks
        add_action('updated_option', [$this, 'log_critical_option_update'], 10, 3);
    }

    /**
     * Core logging function.
     *
     * @param string $action_type e.g. 'login_success', 'post_created'
     * @param string $details A human-readable description of what was done
     * @param int|null $user_id Optional user ID override
     */
    public static function log($action_type, $details, $user_id = null) {
        global $wpdb;
        $audit_table = Database::get_audit_table();

        // Check if database table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        if ($wpdb->get_var("SHOW TABLES LIKE '$audit_table'") === null) {
            return;
        }

        // Determine user
        if ($user_id === null) {
            $current_user = wp_get_current_user();
            $user_id = $current_user ? $current_user->ID : 0;
            $username = $current_user && $current_user->exists() ? $current_user->user_login : __('Sistema/Invitado', 'apta-shield');
        } else {
            $user = get_userdata($user_id);
            $username = $user ? $user->user_login : __('Usuario desconocido', 'apta-shield');
        }

        // Get IP Address (use IpResolver to avoid X-Forwarded-For spoofing).
        $ip = IpResolver::get_client_ip();

        // Insert log
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $audit_table,
            [
                'user_id'     => $user_id,
                'username'    => $username,
                'action_type' => $action_type,
                'ip_address'  => $ip,
                'details'     => $details,
                'created_at'  => current_time('mysql')
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s']
        );
    }

    /* ----------------------------------------------------
     * SESSION LOGGER HANDLERS
     * ---------------------------------------------------- */

    public function log_login_success($user_login, $user) {
        // translators: %s: Username.
        self::log('login_success', sprintf(__('Inicio de sesión exitoso para el usuario: %s', 'apta-shield'), $user_login), $user->ID);
    }

    public function log_login_failure($username) {
        // translators: %s: Username.
        self::log('login_failed', sprintf(__('Intento fallido de inicio de sesión para el usuario: %s', 'apta-shield'), $username), 0);
    }

    public function log_logout() {
        $user = wp_get_current_user();
        if ($user && $user->exists()) {
            // translators: %s: Username.
            self::log('logout', sprintf(__('Cierre de sesión para el usuario: %s', 'apta-shield'), $user->user_login), $user->ID);
        }
    }

    /* ----------------------------------------------------
     * CONTENT LOGGER HANDLERS
     * ---------------------------------------------------- */

    public function log_post_transition($new_status, $old_status, $post) {
        // Ignore automatic autosaves and revisions
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
        if (wp_is_post_revision($post->ID)) return;
        if (wp_is_post_autosave($post->ID)) return;
        if (!in_array($post->post_type, ['post', 'page'])) return; // only track core contents for sanity

        $post_title = get_the_title($post->ID);
        $post_type_label = $post->post_type === 'page' ? __('Página', 'apta-shield') : __('Entrada', 'apta-shield');

        if ($old_status === 'new' && $new_status === 'publish') {
            // translators: 1: Post type label (e.g. Page/Post), 2: Post title, 3: Post ID.
            self::log('post_created', sprintf(__('Creado y publicado: %1$s "%2$s" (ID: %3$d)', 'apta-shield'), $post_type_label, $post_title, $post->ID));
        } elseif ($old_status !== 'publish' && $new_status === 'publish') {
            // translators: 1: Post type label (e.g. Page/Post), 2: Post title, 3: Post ID.
            self::log('post_published', sprintf(__('Publicado: %1$s "%2$s" (ID: %3$d)', 'apta-shield'), $post_type_label, $post_title, $post->ID));
        } elseif ($old_status === 'publish' && $new_status === 'trash') {
            // translators: 1: Post type label (e.g. Page/Post), 2: Post title, 3: Post ID.
            self::log('post_trashed', sprintf(__('Enviado a la papelera: %1$s "%2$s" (ID: %3$d)', 'apta-shield'), $post_type_label, $post_title, $post->ID));
        } elseif ($old_status === 'publish' && $new_status === 'draft') {
            // translators: 1: Post type label (e.g. Page/Post), 2: Post title, 3: Post ID.
            self::log('post_drafted', sprintf(__('Despublicado a borrador: %1$s "%2$s" (ID: %3$d)', 'apta-shield'), $post_type_label, $post_title, $post->ID));
        } elseif ($old_status === 'publish' && $new_status === 'publish') {
            // translators: 1: Post type label (e.g. Page/Post), 2: Post title, 3: Post ID.
            self::log('post_updated', sprintf(__('Actualizado: %1$s "%2$s" (ID: %3$d)', 'apta-shield'), $post_type_label, $post_title, $post->ID));
        }
    }

    public function log_post_deletion($post_id) {
        $post = get_post($post_id);
        if (!$post || wp_is_post_revision($post_id) || !in_array($post->post_type, ['post', 'page'])) {
            return;
        }
        $post_title = get_the_title($post_id);
        $post_type_label = $post->post_type === 'page' ? __('Página', 'apta-shield') : __('Entrada', 'apta-shield');
        // translators: 1: Post type label (e.g. Page/Post), 2: Post title, 3: Post ID.
        self::log('post_deleted', sprintf(__('Eliminado permanentemente: %1$s "%2$s" (ID: %3$d)', 'apta-shield'), $post_type_label, $post_title, $post_id));
    }

    /* ----------------------------------------------------
     * PLUGINS & THEMES LOGGER HANDLERS
     * ---------------------------------------------------- */

    public function log_plugin_activation($plugin, $network_wide) {
        // translators: %s: Plugin path/name.
        self::log('plugin_activated', sprintf(__('Plugin activado: %s', 'apta-shield'), $plugin));
    }

    public function log_plugin_deactivation($plugin, $network_wide) {
        // translators: %s: Plugin path/name.
        self::log('plugin_deactivated', sprintf(__('Plugin desactivado: %s', 'apta-shield'), $plugin));
    }

    public function log_theme_switch($new_name, $new_theme) {
        // translators: %s: Theme name.
        self::log('theme_switched', sprintf(__('Tema activo cambiado a: %s', 'apta-shield'), $new_name));
    }

    /* ----------------------------------------------------
     * USER PROFILE LOGGER HANDLERS
     * ---------------------------------------------------- */

    public function log_user_registration($user_id) {
        $user = get_userdata($user_id);
        $role = !empty($user->roles) ? implode(', ', $user->roles) : __('ninguno', 'apta-shield');
        // translators: 1: Username, 2: User role(s), 3: User ID.
        self::log('user_registered', sprintf(__('Nuevo usuario registrado: %1$s (Rol: %2$s, ID: %3$d)', 'apta-shield'), $user->user_login, $role, $user_id));
    }

    public function log_user_deletion($user_id) {
        $user = get_userdata($user_id);
        if ($user) {
            // translators: 1: Username, 2: User ID.
            self::log('user_deleted', sprintf(__('Usuario eliminado: %1$s (ID: %2$d)', 'apta-shield'), $user->user_login, $user_id));
        }
    }

    public function log_profile_update($user_id, $old_user_data) {
        $user = get_userdata($user_id);
        // translators: 1: Username, 2: User ID.
        self::log('profile_updated', sprintf(__('Perfil de usuario actualizado: %1$s (ID: %2$d)', 'apta-shield'), $user->user_login, $user_id));
    }

    /* ----------------------------------------------------
     * SETTINGS LOGGER HANDLERS
     * ---------------------------------------------------- */

    public function log_critical_option_update($option, $old_value, $value) {
        $tracked_options = [
            'siteurl'                    => __('URL del Sitio (siteurl)', 'apta-shield'),
            'home'                       => __('URL de Inicio (home)', 'apta-shield'),
            'admin_email'                => __('Correo del Administrador', 'apta-shield'),
            'users_can_register'         => __('Opción de registro de usuarios (Cualquiera puede registrarse)', 'apta-shield'),
            'apta_shield_settings' => __('Ajustes de Apta Shield', 'apta-shield')
        ];

        if (array_key_exists($option, $tracked_options)) {
            // Avoid logging if values are identical
            if ($old_value === $value) return;

            // Formulate details representation
            $label = $tracked_options[$option];
            // translators: %s: Option label/name.
            self::log('setting_changed', sprintf(__('Ajuste crítico cambiado: %s', 'apta-shield'), $label));
        }
    }
}
