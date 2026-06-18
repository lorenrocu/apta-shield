<?php

namespace AptaShield\Core;

defined('ABSPATH') || exit;

use AptaShield\Common\Database;
use AptaShield\Modules\Firewall\Firewall;
use AptaShield\Modules\BruteForce\BruteForce;
use AptaShield\Modules\UrlObfuscator\UrlObfuscator;
use AptaShield\Modules\Scanner\Scanner;
use AptaShield\Modules\Reinstaller\Reinstaller;
use AptaShield\Modules\Notifier\Notifier;
use AptaShield\Modules\AuditLog\AuditLog;
use AptaShield\Modules\Hardening\Hardening;
use AptaShield\Admin\Dashboard;

/**
 * Class Plugin
 * The core controller that bootstrap Apta Shield modules.
 */
class Plugin {
    
    /**
     * Singleton instance.
     *
     * @var Plugin|null
     */
    private static $instance = null;

    /**
     * Active modules.
     *
     * @var array
     */
    private $modules = [];

    /**
     * Get instance of Plugin.
     *
     * @return Plugin
     */
    public static function get_instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor.
     */
    private function __construct() {
        // Run early firewall check before any other plugin logic
        $this->early_waf_check();
    }

    /**
     * Early Firewall (WAF) execution.
     * Needs to run before anything else loads, even before init.
     */
    private function early_waf_check() {
        // We will initialize the Firewall module early so it can block requests before WP fully boots
        if ($this->is_module_enabled('firewall')) {
            $firewall = new Firewall();
            $firewall->early_block_check();
            $this->modules['firewall'] = $firewall;
        }
    }

    /**
     * Initialize the plugin.
     */
    public function init() {
        // Run database migration check
        $this->maybe_upgrade_database();

        // 0. Initialize Audit Log (active at all times for tracking)
        $this->modules['audit_log'] = new AuditLog();
        $this->modules['audit_log']->run();

        // 0.1. Initialize Hardening filters and hooks
        $this->modules['hardening'] = new Hardening();
        $this->modules['hardening']->run();

        // 1. Initialize Brute Force
        if ($this->is_module_enabled('brute_force')) {
            $this->modules['brute_force'] = new BruteForce();
            $this->modules['brute_force']->run();
        }

        // 2. Initialize URL Obfuscator
        if ($this->is_module_enabled('url_obfuscator')) {
            $this->modules['url_obfuscator'] = new UrlObfuscator();
            $this->modules['url_obfuscator']->run();
        }

        // 3. Initialize Notifier
        if ($this->is_module_enabled('notifier')) {
            $this->modules['notifier'] = new Notifier();
            $this->modules['notifier']->run();
        }

        // 4. Initialize Scanner and Reinstaller (always loaded for admin and CLI/cron tasks)
        $this->modules['scanner'] = new Scanner();
        $this->modules['scanner']->run();

        $this->modules['reinstaller'] = new Reinstaller();
        $this->modules['reinstaller']->run();

        // 5. Initialize Admin Panel (Dashboard)
        if (is_admin() || wp_doing_ajax()) {
            $this->modules['admin'] = new Dashboard($this);
            $this->modules['admin']->run();
        }

        // Register Activation/Deactivation hooks
        register_activation_hook(APTA_SHIELD_FILE, [$this, 'activate']);
        register_deactivation_hook(APTA_SHIELD_FILE, [$this, 'deactivate']);
    }

    /**
     * Check if a module is enabled in settings.
     *
     * @param string $module
     * @return bool
     */
    public function is_module_enabled($module) {
        $settings = $this->get_settings();
        switch ($module) {
            case 'firewall':
                return !empty($settings['firewall_enabled']);
            case 'brute_force':
                return !empty($settings['brute_force_enabled']);
            case 'url_obfuscator':
                return !empty($settings['url_obfuscator_enabled']);
            case 'notifier':
                return !empty($settings['notifier_enabled']);
            default:
                return true;
        }
    }

    /**
     * Get plugin settings.
     *
     * @return array
     */
    public function get_settings() {
        $defaults = [
            'firewall_enabled'             => true,
            'brute_force_enabled'          => true,
            'brute_force_max_attempts'     => 5,
            'brute_force_lockout_duration' => 60, // in minutes
            'url_obfuscator_enabled'       => false,
            'url_obfuscator_slug'          => 'mi-login-secreto',
            'scanner_auto_scan'            => true,
            'scanner_auto_recovery'        => false,
            'notifier_enabled'             => true,
            'notifier_email'               => get_option('admin_email'),
            'hardening_headers'            => true,
            'hardening_file_edit'          => false,
            'hardening_xmlrpc'             => true,
            'hardening_wp_version'         => true,
            'hardening_author_scan'        => true,
            'trusted_proxies'              => [], // Stored separately as a WP option
        ];

        $settings = get_option('apta_shield_settings', []);

        // Trusted proxies are stored in their own option (see IpResolver::OPTION_KEY)
        // because they can grow large and they are an array, not a scalar. The
        // general settings option stays small and easy to merge.
        $settings['trusted_proxies'] = \AptaShield\Common\IpResolver::get_trusted_proxies();

        return array_merge($defaults, $settings);
    }

    /**
     * Get a registered module.
     *
     * @param string $key
     * @return mixed|null
     */
    public function get_module($key) {
        return isset($this->modules[$key]) ? $this->modules[$key] : null;
    }

    /**
     * Plugin activation handler.
     */
    public function activate() {
        // Create custom database tables
        Database::create_tables();

        // Initialize default options
        if (get_option('apta_shield_settings') === false) {
            update_option('apta_shield_settings', $this->get_settings());
        }

        // Schedule cron for scans
        if (!wp_next_scheduled('apta_shield_daily_scan')) {
            wp_schedule_event(time(), 'daily', 'apta_shield_daily_scan');
        }

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation handler.
     */
    public function deactivate() {
        // Clear scheduled cron jobs
        wp_clear_scheduled_hook('apta_shield_daily_scan');

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Run database table creation if database version is outdated.
     */
    private function maybe_upgrade_database() {
        $db_version = get_option('apta_shield_db_version', '0');
        if (version_compare($db_version, APTA_SHIELD_VERSION, '<')) {
            Database::create_tables();
            update_option('apta_shield_db_version', APTA_SHIELD_VERSION);
        }
    }
}
