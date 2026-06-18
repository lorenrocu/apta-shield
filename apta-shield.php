<?php
/**
 * Plugin Name:       Apta Shield
 * Plugin URI:        https://github.com/lorenrocu/apta-shield
 * Description:       A comprehensive security solution for WordPress, including Malware Scanning, File Integrity Monitoring, WordPress Core Reinstallation, Firewall (WAF), Brute-Force Protection, and URL Obfuscation.
 * Version:           1.1.0
 * Author:            Lorenzo Romero (megapattern)
 * Author URI:        https://lorenzoromero.net.pe
 * License:           GPL-2.0-or-later
 * Text Domain:       apta-shield
 */

defined('ABSPATH') || exit;

// Define plugin constants
define('APTA_SHIELD_VERSION', '1.1.0');
define('APTA_SHIELD_FILE', __FILE__);
define('APTA_SHIELD_PATH', plugin_dir_path(__FILE__));
define('APTA_SHIELD_URL', plugin_dir_url(__FILE__));

// Custom PSR-4 Fallback Autoloader
spl_autoload_register(function ($class) {
    // Prefix for our namespace
    $prefix = 'AptaShield\\';

    // Base directory for the namespace prefix
    $base_dir = APTA_SHIELD_PATH . 'src/';

    // Does the class use the namespace prefix?
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        // No, move to the next registered autoloader
        return;
    }

    // Get the relative class name
    $relative_class = substr($class, $len);

    // Replace namespace separators with directory separators and append .php
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    // If the file exists, load it
    if (file_exists($file)) {
        require $file;
    }
});

// Initialize the plugin
function apta_shield_bootstrap() {
    $plugin = AptaShield\Core\Plugin::get_instance();
    $plugin->init();
}

// Bootstrap early or on plugins_loaded
apta_shield_bootstrap();
