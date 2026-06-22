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
        add_action('wp_ajax_apta_shield_clean_threat', [$this, 'ajax_clean_threat']);
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

            // 2. Explainable local risk analysis. It combines IOCs and behaviour;
            // it never executes or attempts to decrypt untrusted code.
            $finding = FileAnalyzer::analyse($file_path, $relative_path);
            if ($finding) {
                $threats[] = [
                    'file'       => $relative_path,
                    'type'       => 'malware',
                    'type_label' => $finding['label'],
                    'desc'       => $finding['desc'],
                    'risk_score' => $finding['score'],
                    'reasons'    => $finding['reasons'],
                ];
                $logs[] = sprintf(__('[x] Riesgo de malware encontrado en: %1$s (%2$s)', 'apta-shield'), $relative_path, $finding['label']);
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

        // Report detections to Megapattern API Hub for global malware telemetry (free tier)
        if (!empty($threats)) {
            $this->report_threats_to_cloud($threats);
        }

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

        // Root loaders and server configuration are common persistence points.
        foreach (['.htaccess', '.user.ini', 'php.ini', 'wp-config.php', 'wp-settings.php', 'wp-load.php'] as $root_file) {
            if (is_file($root . $root_file)) {
                $files[] = wp_normalize_path($root . $root_file);
            }
        }

        // MU plugins load before normal plugins and are frequently abused for persistence.
        // They must be scanned explicitly: they are not children of wp-content/plugins.
        $scan_dirs = ['wp-admin', 'wp-includes', 'wp-content/themes', 'wp-content/plugins', 'wp-content/mu-plugins', 'wp-content/uploads', 'wp-content/cache', 'wp-content/upgrade'];
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
                if ($this->is_scannable_file($path)) {
                    $results[] = wp_normalize_path($path);
                }
            } elseif ($value !== '.' && $value !== '..') {
                // Scan uploads/cache/backups too: attackers routinely hide PHP there.
                // node_modules is excluded because it is dependency source, not web payload.
                if ($value === 'node_modules') {
                    continue;
                }
                $this->get_files_recursive($path, $results);
            }
        }
    }

    /**
     * Scan PHP and common alternate PHP extensions, including .htaccess files.
     */
    private function is_scannable_file($path) {
        $basename = strtolower(basename($path));
        if (in_array($basename, ['.htaccess', '.user.ini', 'php.ini'], true)) {
            return true;
        }

        return in_array(strtolower(pathinfo($path, PATHINFO_EXTENSION)), ['php', 'phtml', 'pht', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8'], true);
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
     * Delete a malware file that was found by this scanner.
     *
     * The operation is deliberately restricted to wp-content. Core files and
     * arbitrary paths can never be removed through this endpoint.
     */
    public function ajax_clean_threat() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        $threat_index = isset($_POST['threat_index']) ? intval(wp_unslash($_POST['threat_index'])) : -1;
        $results = get_option('apta_shield_last_scan_result', []);

        if ($threat_index < 0 || empty($results['threats']) || empty($results['threats'][$threat_index])) {
            wp_send_json_error(__('Amenaza no válida o resultado de análisis caducado.', 'apta-shield'));
        }

        $threat = $results['threats'][$threat_index];
        $relative_path = ltrim((string) $threat['file'], '/');
        $allowed_prefixes = ['wp-content/plugins/', 'wp-content/mu-plugins/'];
        $is_allowed_path = false;
        foreach ($allowed_prefixes as $prefix) {
            if (strpos($relative_path, $prefix) === 0) {
                $is_allowed_path = true;
                break;
            }
        }

        if (($threat['type'] ?? '') !== 'malware' || !$is_allowed_path) {
            wp_send_json_error(__('Por seguridad, solo se eliminan archivos de malware detectados dentro de plugins o mu-plugins.', 'apta-shield'));
        }

        $file_path = wp_normalize_path(ABSPATH . $relative_path);
        $content_dir = trailingslashit(wp_normalize_path(WP_CONTENT_DIR));
        if (strpos($file_path, $content_dir) !== 0 || !is_file($file_path) || !Quarantine::isolate($file_path, $relative_path)) {
            wp_send_json_error(__('No se pudo poner el archivo en cuarentena. Comprueba los permisos del servidor.', 'apta-shield'));
        }

        unset($results['threats'][$threat_index]);
        $results['threats'] = array_values($results['threats']);
        $results['malware_count'] = count(array_filter($results['threats'], function ($item) {
            return ($item['type'] ?? '') === 'malware';
        }));
        $results['core_modified_count'] = count(array_filter($results['threats'], function ($item) {
            return ($item['type'] ?? '') === 'core_modified';
        }));
        update_option('apta_shield_last_scan_result', $results);

        wp_send_json_success(__('Archivo malicioso aislado en cuarentena. Ejecuta otro análisis completo para buscar persistencia adicional.', 'apta-shield'));
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

            $finding = FileAnalyzer::analyse($file_path, $relative_path);
            if ($finding) {
                $threats[] = [
                    'file'       => $relative_path,
                    'type'       => 'malware',
                    'type_label' => $finding['label'],
                    'desc'       => $finding['desc'],
                    'risk_score' => $finding['score'],
                    'reasons'    => $finding['reasons'],
                ];
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

        // Report detections to Megapattern API Hub for global malware telemetry (free tier)
        if (!empty($threats)) {
            $this->report_threats_to_cloud($threats);
        }

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

    /**
     * Report detected threats to the Megapattern Central API Hub.
     *
     * This method is called by both the interactive scan and the daily cron.
     * It sends a lightweight POST request to the free telemetry endpoint
     * (/api/v1/shield/malware/report-threats-free) using the special sentinel
     * license value 'free'. The API Hub stores the findings to grow the global
     * malware signature database without requiring a paid license.
     *
     * The request is fire-and-forget: failures are logged to the WP error log
     * but never bubble up to the user interface.
     *
     * @param array $threats Flat array of threat records detected during the scan.
     */
    private function report_threats_to_cloud( array $threats ) {
        $payload = [
            'scan_time'     => current_time( 'c' ),
            'total_threats' => count( $threats ),
            'threats'       => $threats,
        ];

        $response = wp_remote_post(
            'https://megapattern-system.vercel.app/api/v1/shield/malware/report-threats-free',
            [
                'timeout'     => 8,
                'blocking'    => false, // fire-and-forget: do not wait for response
                'headers'     => [
                    'Content-Type'   => 'application/json',
                    'X-Apta-License' => 'free',
                    'X-Apta-Domain'  => esc_url_raw( home_url() ),
                    'X-Apta-Product' => 'apta-shield',
                ],
                'body'        => wp_json_encode( $payload ),
                'data_format' => 'body',
            ]
        );

        if ( is_wp_error( $response ) ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log( '[Apta Shield] Telemetry report failed: ' . $response->get_error_message() );
        }
    }
}
