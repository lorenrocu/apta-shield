<?php

namespace AptaShield\Modules\Scanner;

defined('ABSPATH') || exit;

/** Safely isolates detected files for recovery instead of deleting them outright. */
class Quarantine {

    /**
     * @param string $file_path Absolute path of a verified detected malware file.
     * @param string $relative_path Original relative path.
     * @return string|false Quarantine path on success.
     */
    public static function isolate($file_path, $relative_path) {
        if (!is_file($file_path) || !defined('WP_CONTENT_DIR')) {
            return false;
        }

        $directory = trailingslashit(WP_CONTENT_DIR) . 'apta-shield-quarantine';
        if (!is_dir($directory) && !wp_mkdir_p($directory)) {
            return false;
        }

        // Block direct web access on Apache installations. Files are also given
        // a non-executable extension to prevent accidental execution elsewhere.
        $deny_file = $directory . '/.htaccess';
        if (!file_exists($deny_file)) {
            @file_put_contents($deny_file, "Deny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n");
        }
        if (!file_exists($directory . '/index.php')) {
            @file_put_contents($directory . '/index.php', "<?php // Silence is golden.\n");
        }

        $id = gmdate('Ymd-His') . '-' . substr(hash_file('sha256', $file_path), 0, 16);
        $target = $directory . '/' . $id . '.quarantine';
        if (!@rename($file_path, $target)) {
            if (!@copy($file_path, $target) || !@unlink($file_path)) {
                return false;
            }
        }

        @file_put_contents($directory . '/' . $id . '.json', wp_json_encode([
            'original_path' => $relative_path,
            'quarantined_at' => current_time('mysql', true),
            'sha256' => hash_file('sha256', $target),
        ]));

        return $target;
    }
}
