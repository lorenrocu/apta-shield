<?php

namespace AptaShield\Modules\Reinstaller;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Core\Plugin;
use AptaShield\Common\Database;
use AptaShield\Common\IpResolver;

/**
 * Class Reinstaller
 * Manages downloading and replacing WordPress core files.
 */
class Reinstaller implements ModuleInterface {

    /**
     * Start the module.
     */
    public function run() {
        add_action('wp_ajax_apta_shield_reinstall_core', [$this, 'ajax_reinstall_core']);
    }

    /**
     * AJAX handler to trigger core reinstallation manually.
     */
    public function ajax_reinstall_core() {
        check_ajax_referer('apta_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permisos insuficientes.', 'apta-shield'), 403);
        }

        $result = $this->execute_reinstallation();

        if ($result === true) {
            // Log event
            $this->log_reinstall_event('manual_success', __('Reinstalación del núcleo ejecutada con éxito de forma manual.', 'apta-shield'));
            wp_send_json_success(__('WordPress Core reinstalado de forma exitosa.', 'apta-shield'));
        } else {
            // Log event
            // translators: %s: Error message detail.
            $this->log_reinstall_event('manual_fail', sprintf(__('Fallo en la reinstalación: %s', 'apta-shield'), $result));
            // translators: %s: Error message detail.
            wp_send_json_error(sprintf(__('Error al reinstalar: %s', 'apta-shield'), $result));
        }
    }

    /**
     * Perform the WordPress Core download, extraction and safe file overwrite.
     *
     * @return bool|string True on success, error message on failure.
     */
    public function execute_reinstallation() {
        global $wp_version;

        // 1. Initialize WP_Filesystem
        require_once ABSPATH . 'wp-admin/includes/file.php';
        if (!function_exists('WP_Filesystem')) {
            return __('Función WP_Filesystem no disponible.', 'apta-shield');
        }

        // Attempt direct context, or fallback to default
        if (!WP_Filesystem()) {
            return __('No se pudo inicializar la API de archivos de WordPress.', 'apta-shield');
        }

        global $wp_filesystem;

        // 2. Prepare Temp Paths
        $uploads_dir = wp_upload_dir();
        if (!empty($uploads_dir['error'])) {
            // translators: %s: Directory error message.
            return sprintf(__('Directorio de subidas inaccesible: %s', 'apta-shield'), $uploads_dir['error']);
        }

        $temp_root = wp_normalize_path($uploads_dir['basedir'] . '/apta-temp');
        $zip_file_path = $temp_root . '/wordpress-core.zip';
        $extract_to_path = $temp_root . '/extracted';

        // Clean any old temp directory
        if ($wp_filesystem->is_dir($temp_root)) {
            $wp_filesystem->delete($temp_root, true);
        }

        // Create fresh temp dirs
        if (!$wp_filesystem->mkdir($temp_root) || !$wp_filesystem->mkdir($extract_to_path)) {
            return __('No se pudieron crear directorios temporales en wp-content/uploads.', 'apta-shield');
        }

        // 3. Download WordPress Core ZIP
        $zip_url = "https://wordpress.org/wordpress-{$wp_version}.zip";
        $downloaded_file = download_url($zip_url);

        if (is_wp_error($downloaded_file)) {
            $wp_filesystem->delete($temp_root, true);
            // translators: %s: Download error message.
            return sprintf(__('Fallo al descargar el archivo ZIP: %s', 'apta-shield'), $downloaded_file->get_error_message());
        }

        // Move downloaded temp file to our custom zip file path
        if (!$wp_filesystem->move($downloaded_file, $zip_file_path, true)) {
            $wp_filesystem->delete($temp_root, true);
            wp_delete_file($downloaded_file);
            return __('No se pudo ubicar el paquete descargado en la carpeta temporal.', 'apta-shield');
        }

        // 4. Unzip Core Package
        $unzipped = unzip_file($zip_file_path, $extract_to_path);
        if (is_wp_error($unzipped)) {
            $wp_filesystem->delete($temp_root, true);
            // translators: %s: Extraction error message.
            return sprintf(__('Fallo al descomprimir el ZIP: %s', 'apta-shield'), $unzipped->get_error_message());
        }

        // The unzip creates a 'wordpress/' subdirectory
        $extracted_wordpress_dir = $extract_to_path . '/wordpress';
        if (!$wp_filesystem->is_dir($extracted_wordpress_dir)) {
            $wp_filesystem->delete($temp_root, true);
            return __('No se encontró la carpeta de WordPress esperada en el paquete descomprimido.', 'apta-shield');
        }

        // 5. SECURE STRIPPING: Exclude wp-content and config samples from the source
        $wp_content_src = $extracted_wordpress_dir . '/wp-content';
        if ($wp_filesystem->is_dir($wp_content_src)) {
            $wp_filesystem->delete($wp_content_src, true); // Keep it completely safe!
        }
        
        $wp_config_sample = $extracted_wordpress_dir . '/wp-config-sample.php';
        if ($wp_filesystem->exists($wp_config_sample)) {
            $wp_filesystem->delete($wp_config_sample);
        }

        // 6. Copy Files Recursively to ABSPATH
        $abspath_normalized = wp_normalize_path(ABSPATH);
        
        $this->copy_directory_recursive($extracted_wordpress_dir, $abspath_normalized);

        // 7. Cleanup
        $wp_filesystem->delete($temp_root, true);

        // Log to Audit Log
        \AptaShield\Modules\AuditLog\AuditLog::log(
            'core_reinstalled',
            __('Reinstalación limpia del núcleo de WordPress (Core) completada con éxito.', 'apta-shield')
        );

        // Trigger email notification of core restore
        $notifier = Plugin::get_instance()->get_module('notifier');
        if ($notifier) {
            $notifier->send_reinstall_alert();
        }

        return true;
    }

    /**
     * Copy directories recursively using WP_Filesystem.
     *
     * @param string $from
     * @param string $to
     */
    private function copy_directory_recursive($from, $to) {
        global $wp_filesystem;
        
        $dirlist = $wp_filesystem->dirlist($from);
        if (empty($dirlist)) {
            return;
        }

        foreach ($dirlist as $name => $info) {
            $src_path  = $from . '/' . $name;
            $dest_path = $to . '/' . $name;

            if ($info['type'] === 'd') {
                if (!$wp_filesystem->is_dir($dest_path)) {
                    $wp_filesystem->mkdir($dest_path, FS_CHMOD_DIR);
                }
                $this->copy_directory_recursive($src_path, $dest_path);
            } else {
                // Check if destination file exists and is writable, then copy
                $wp_filesystem->copy($src_path, $dest_path, true, FS_CHMOD_FILE);
            }
        }
    }

    /**
     * Log the reinstallation events in logs table.
     *
     * @param string $status
     * @param string $details_text
     */
    private function log_reinstall_event($status, $details_text) {
        global $wpdb;
        $logs_table = Database::get_logs_table();

        $ip = IpResolver::get_client_ip();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $logs_table,
            [
                'event_type' => 'core_reinstall',
                'ip_address' => $ip,
                'details'    => json_encode(['status' => $status, 'message' => $details_text]),
                'created_at' => current_time('mysql')
            ],
            ['%s', '%s', '%s', '%s']
        );
    }
}
