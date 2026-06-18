<?php

namespace AptaShield\Modules\Scanner;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Core\Plugin;
use AptaShield\Common\Database;

/**
 * Class Scanner
 * Coordinates malware and integrity scanning.
 */
class Scanner implements ModuleInterface {

    /**
     * Start the module.
     */
    public function run() {
        // Register scan AJAX endpoints
        add_action('wp_ajax_apta_shield_run_scan', [$this, 'ajax_run_scan']);
        add_action('apta_shield_daily_scan', [$this, 'execute_daily_scan_cron']);
    }

    /**
     * AJAX router to run the scanner in batches.
     */
    public function ajax_run_scan() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        $step = isset($_POST['step']) ? sanitize_text_field(wp_unslash($_POST['step'])) : 'start';
        $progress = isset($_POST['progress']) ? intval(wp_unslash($_POST['progress'])) : 0;

        if ($step === 'start') {
            $this->start_scan_initialization();
        } else {
            $this->continue_scan_process($progress);
        }
    }

    /**
     * Initialize the scan state: build list of files and fetch checksums.
     */
    private function start_scan_initialization() {
        global $wp_version;

        $logs = [];
        $logs[] = __('Descargando checksums oficiales de WordPress.org...', 'apta-shield');

        // Fetch core checksums
        $locale = get_locale();
        $api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
        
        $response = wp_remote_get($api_url);
        $checksums = [];
        
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            if (!empty($body['checksums'])) {
                $checksums = $body['checksums'];
                // translators: %s: WordPress version number.
                $logs[] = sprintf(__('Checksums de WordPress %s descargados correctamente.', 'apta-shield'), $wp_version);
            }
        }

        if (empty($checksums)) {
            // Fallback to English US checksum API if localized fails
            $api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}";
            $response = wp_remote_get($api_url);
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                if (!empty($body['checksums'])) {
                    $checksums = $body['checksums'];
                    // translators: %s: WordPress version number.
                    $logs[] = sprintf(__('Checksums descargados (Fallback en_US) para WordPress %s.', 'apta-shield'), $wp_version);
                }
            }
        }

        if (empty($checksums)) {
            $logs[] = __('No se pudieron obtener checksums oficiales. Se omitirá la validación de integridad del core.', 'apta-shield');
        }

        $logs[] = __('Buscando archivos PHP en la instalación...', 'apta-shield');

        // Gather all PHP files in ABSPATH
        $files = $this->gather_php_files();
        // translators: %d: Total number of PHP files found.
        $logs[] = sprintf(__('Encontrados %d archivos PHP para analizar.', 'apta-shield'), count($files));

        // Save scan state to transients
        set_transient('apta_scan_files_list', $files, 600); // 10 minutes cache
        set_transient('apta_scan_checksums', $checksums, 600);
        
        // Reset threats temporary store
        delete_option('apta_scan_threats_temp');

        wp_send_json_success([
            'status'     => 'running',
            'percent'    => 5,
            'next_step'  => 'scan',
            'progress'   => 0,
            'logs'       => $logs
        ]);
    }

    /**
     * Scan a chunk of files.
     *
     * @param int $progress The index inside files list to start from.
     */
    private function continue_scan_process($progress) {
        $files = get_transient('apta_scan_files_list');
        $checksums = get_transient('apta_scan_checksums');

        if ($files === false) {
            wp_send_json_error(__('Sesión de escaneo expirada. Por favor, reinicia.', 'apta-shield'));
        }

        $checksums = is_array($checksums) ? $checksums : [];
        $total_files = count($files);

        if ($total_files === 0) {
            $this->complete_scan([], $checksums);
            return;
        }

        $chunk_size = 60; // files per ajax request
        $start_index = $progress;
        $end_index = min($total_files, $start_index + $chunk_size);
        
        $threats = get_option('apta_scan_threats_temp', []);
        $logs = [];

        $signatures = Signatures::get_signatures();
        $abspath_normalized = wp_normalize_path(ABSPATH);

        $plugin_dir = dirname(plugin_basename(APTA_SHIELD_FILE));
        $plugin_rel_path = 'wp-content/plugins/' . $plugin_dir . '/';

        for ($i = $start_index; $i < $end_index; $i++) {
            $file_path = $files[$i];
            if (!file_exists($file_path)) {
                continue;
            }

            $relative_path = str_replace($abspath_normalized, '', wp_normalize_path($file_path));
            
            // Skip scanning the security plugin itself to prevent signature self-matching false positives
            if (strpos(ltrim($relative_path, '/'), $plugin_rel_path) === 0) {
                continue;
            }

            $is_core_file = $this->is_wp_core_file($relative_path, $checksums);

            // 1. Core Integrity Check
            if ($is_core_file && isset($checksums[$relative_path])) {
                $local_md5 = md5_file($file_path);
                if ($local_md5 !== $checksums[$relative_path]) {
                    $threats[] = [
                        'file'       => $relative_path,
                        'type'       => 'core_modified',
                        'type_label' => __('Core Modificado', 'apta-shield'),
                        'desc'       => __('El hash del archivo no coincide con la firma oficial de WordPress.', 'apta-shield')
                    ];
                    // translators: %s: Relative path of the modified core file.
                    $logs[] = sprintf(__('[!] Archivo del Core alterado detectado: %s', 'apta-shield'), $relative_path);
                }
            }

            // 2. Heuristic Signature Check (read first 1MB of file content)
            $content = file_get_contents($file_path, false, null, 0, 1024 * 1024);
            if (!empty($content)) {
                foreach ($signatures as $sig) {
                    if (preg_match($sig['pattern'], $content)) {
                        $threats[] = [
                            'file'       => $relative_path,
                            'type'       => 'malware',
                            'type_label' => $sig['label'],
                            'desc'       => $sig['desc']
                        ];
                        // translators: 1: File path, 2: Malware signature label.
                        $logs[] = sprintf(__('[x] Malware encontrado en: %1$s (%2$s)', 'apta-shield'), $relative_path, $sig['label']);
                        break; // Stop after first match in a file
                    }
                }
            }
        }

        // Save current threats back to temp option
        update_option('apta_scan_threats_temp', $threats);

        // Check if we are done
        $percent = min(99, round(($end_index / $total_files) * 95) + 5);

        if ($end_index >= $total_files) {
            $this->complete_scan($threats, $checksums);
        } else {
            wp_send_json_success([
                'status'    => 'running',
                'percent'   => $percent,
                'next_step' => 'scan',
                'progress'  => $end_index,
                'logs'      => $logs
            ]);
        }
    }

    /**
     * Wrap up the scan, save findings and notify admin if needed.
     *
     * @param array $threats
     * @param array $checksums
     */
    private function complete_scan($threats, $checksums) {
        // Verify core missing files (checksums that are not present locally)
        $core_modified_count = 0;
        $malware_count = 0;

        foreach ($threats as $threat) {
            if ($threat['type'] === 'core_modified') {
                $core_modified_count++;
            } elseif ($threat['type'] === 'malware') {
                $malware_count++;
            }
        }

        // Check for missing core files
        $abspath_normalized = wp_normalize_path(ABSPATH);
        foreach ($checksums as $core_file => $hash) {
            // Check major folders, ignore wp-content
            if (strpos($core_file, 'wp-content/') === 0) continue;
            
            $local_path = $abspath_normalized . $core_file;
            if (!file_exists($local_path)) {
                $threats[] = [
                    'file'       => $core_file,
                    'type'       => 'core_modified',
                    'type_label' => __('Core Eliminado', 'apta-shield'),
                    'desc'       => __('Archivo oficial del núcleo de WordPress ausente en el sistema.', 'apta-shield')
                ];
                $core_modified_count++;
            }
        }

        $logs = [];
        $logs[] = __('Análisis finalizado.', 'apta-shield');
        // translators: %d: Number of modified or missing core files.
        $logs[] = sprintf(__('Total Core Modificados/Ausentes: %d', 'apta-shield'), $core_modified_count);
        // translators: %d: Number of detected malware files.
        $logs[] = sprintf(__('Total Malware Detectados: %d', 'apta-shield'), $malware_count);

        $results = [
            'time'                => time(),
            'malware_count'       => $malware_count,
            'core_modified_count' => $core_modified_count,
            'threats'             => $threats
        ];

        // Save last scan result
        update_option('apta_shield_last_scan_result', $results);

        // Log to Audit Log
        \AptaShield\Modules\AuditLog\AuditLog::log(
            'scan_completed',
            // translators: 1: Total threats found, 2: Modified core files count, 3: Malware files count.
            sprintf(__('Análisis de virus e integridad completado. Amenazas encontradas: %1$d (Core modificado: %2$d, Malware: %3$d).', 'apta-shield'), $malware_count + $core_modified_count, $core_modified_count, $malware_count)
        );

        // Delete transients
        delete_transient('apta_scan_files_list');
        delete_transient('apta_scan_checksums');
        delete_option('apta_scan_threats_temp');

        // Email Alert if enabled
        $notifier = Plugin::get_instance()->get_module('notifier');
        if ($notifier && ($malware_count > 0 || $core_modified_count > 0)) {
            $notifier->send_scan_alert($results);
        }

        // Auto-recovery execution
        $settings = Plugin::get_instance()->get_settings();
        if (!empty($settings['scanner_auto_recovery']) && $core_modified_count > 0) {
            $reinstaller = Plugin::get_instance()->get_module('reinstaller');
            if ($reinstaller) {
                $logs[] = __('[!] Auto-recuperación activa. Iniciando reinstalación automática del núcleo de WordPress...', 'apta-shield');
                $reinstall_result = $reinstaller->execute_reinstallation();
                if ($reinstall_result === true) {
                    $logs[] = __('[+] Auto-recuperación exitosa. WordPress Core ha sido restaurado.', 'apta-shield');
                } else {
                    // translators: %s: Error message detail.
                    $logs[] = sprintf(__('[x] Falló la auto-recuperación: %s', 'apta-shield'), $reinstall_result);
                }
            }
        }

        wp_send_json_success([
            'status'              => 'completed',
            'percent'             => 100,
            'core_modified_count' => $core_modified_count,
            'malware_count'       => $malware_count,
            'threats'             => $threats,
            'logs'                => $logs
        ]);
    }

    /**
     * Gather recursive list of PHP files inside WordPress directory.
     *
     * @return array
     */
    private function gather_php_files() {
        $files = [];
        $root = wp_normalize_path(ABSPATH);

        // Scan Root php files
        $root_files = glob($root . '*.php');
        if (is_array($root_files)) {
            $files = array_merge($files, $root_files);
        }

        // Scan wp-admin, wp-includes and wp-content directories
        $scan_dirs = ['wp-admin', 'wp-includes', 'wp-content/themes', 'wp-content/plugins'];
        foreach ($scan_dirs as $dir) {
            $path = $root . $dir;
            if (is_dir($path)) {
                $this->get_files_recursive($path, $files);
            }
        }

        return $files;
    }

    /**
     * Recursive scan helper.
     *
     * @param string $dir
     * @param array $results
     */
    private function get_files_recursive($dir, &$results = []) {
        $files = @scandir($dir);
        if ($files === false) return;

        foreach ($files as $value) {
            $path = $dir . '/' . $value;
            if (!is_dir($path)) {
                if (pathinfo($path, PATHINFO_EXTENSION) === 'php') {
                    $results[] = wp_normalize_path($path);
                }
            } elseif ($value !== '.' && $value !== '..') {
                // Ignore backup, cache and uploads folders
                if ($value === 'uploads' || $value === 'cache' || $value === 'node_modules' || $value === 'backups') {
                    continue;
                }
                $this->get_files_recursive($path, $results);
            }
        }
    }

    /**
     * Verify if a relative path is a standard WordPress core file.
     *
     * @param string $relative_path
     * @param array $checksums
     * @return bool
     */
    private function is_wp_core_file($relative_path, $checksums) {
        // Core files NEVER live inside wp-content folder
        if (strpos(ltrim($relative_path, '/'), 'wp-content/') === 0) {
            return false;
        }

        // If in checksums array, it is definitely a core file
        if (isset($checksums[$relative_path])) {
            return true;
        }

        return true;
    }

    /**
     * Nightly scan scheduled task via Cron.
     */
    public function execute_daily_scan_cron() {
        $settings = Plugin::get_instance()->get_settings();
        if (empty($settings['scanner_auto_scan'])) {
            return;
        }

        // Since cron runs non-interactively in background, we scan all files in a single run
        global $wp_version;
        $locale = get_locale();
        $api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
        
        $response = wp_remote_get($api_url);
        $checksums = [];
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            if (!empty($body['checksums'])) {
                $checksums = $body['checksums'];
            }
        }

        $files = $this->gather_php_files();
        $threats = [];
        $signatures = Signatures::get_signatures();
        $abspath_normalized = wp_normalize_path(ABSPATH);

        $plugin_dir = dirname(plugin_basename(APTA_SHIELD_FILE));
        $plugin_rel_path = 'wp-content/plugins/' . $plugin_dir . '/';

        foreach ($files as $file_path) {
            if (!file_exists($file_path)) continue;

            $relative_path = str_replace($abspath_normalized, '', wp_normalize_path($file_path));
            
            // Skip scanning the security plugin itself to prevent signature self-matching false positives
            if (strpos(ltrim($relative_path, '/'), $plugin_rel_path) === 0) {
                continue;
            }

            $is_core_file = $this->is_wp_core_file($relative_path, $checksums);

            if ($is_core_file && isset($checksums[$relative_path])) {
                $local_md5 = md5_file($file_path);
                if ($local_md5 !== $checksums[$relative_path]) {
                    $threats[] = [
                        'file'       => $relative_path,
                        'type'       => 'core_modified',
                        'type_label' => __('Core Modificado', 'apta-shield'),
                        'desc'       => __('El hash del archivo no coincide con la firma oficial de WordPress.', 'apta-shield')
                    ];
                }
            }

            $content = file_get_contents($file_path, false, null, 0, 1024 * 1024);
            if (!empty($content)) {
                foreach ($signatures as $sig) {
                    if (preg_match($sig['pattern'], $content)) {
                        $threats[] = [
                            'file'       => $relative_path,
                            'type'       => 'malware',
                            'type_label' => $sig['label'],
                            'desc'       => $sig['desc']
                        ];
                        break;
                    }
                }
            }
        }

        // Verify missing files
        foreach ($checksums as $core_file => $hash) {
            if (strpos($core_file, 'wp-content/') === 0) continue;
            if (!file_exists($abspath_normalized . $core_file)) {
                $threats[] = [
                    'file'       => $core_file,
                    'type'       => 'core_modified',
                    'type_label' => __('Core Eliminado', 'apta-shield'),
                    'desc'       => __('Archivo oficial del núcleo de WordPress ausente en el sistema.', 'apta-shield')
                ];
            }
        }

        $core_modified_count = 0;
        $malware_count = 0;
        foreach ($threats as $threat) {
            if ($threat['type'] === 'core_modified') {
                $core_modified_count++;
            } elseif ($threat['type'] === 'malware') {
                $malware_count++;
            }
        }

        $results = [
            'time'                => time(),
            'malware_count'       => $malware_count,
            'core_modified_count' => $core_modified_count,
            'threats'             => $threats
        ];

        update_option('apta_shield_last_scan_result', $results);

        // Send email alert if threats exist
        $notifier = Plugin::get_instance()->get_module('notifier');
        if ($notifier && ($malware_count > 0 || $core_modified_count > 0)) {
            $notifier->send_scan_alert($results);
        }

        // Auto-recovery if enabled and core files are corrupted
        if (!empty($settings['scanner_auto_recovery']) && $core_modified_count > 0) {
            $reinstaller = Plugin::get_instance()->get_module('reinstaller');
            if ($reinstaller) {
                $reinstaller->execute_reinstallation();
            }
        }
    }
}
