<?php

namespace AptaShield\Modules\Scanner;

defined('ABSPATH') || exit;

/**
 * Stateless local malware analyser.
 *
 * It never executes or decodes a payload. Instead it combines independent
 * behavioural indicators and known signatures into one explainable verdict.
 */
class FileAnalyzer {

    const MAX_BYTES = 2097152; // 2 MiB: enough for PHP loaders without exhausting memory.

    /**
     * Analyse a file and return one actionable finding, or null when clean.
     *
     * @param string $file_path
     * @param string $relative_path
     * @return array|null
     */
    public static function analyse($file_path, $relative_path) {
        $size = @filesize($file_path);
        if ($size === false || $size > 10485760) {
            return null;
        }

        $content = @file_get_contents($file_path, false, null, 0, self::MAX_BYTES);
        if ($content === false || $content === '') {
            return null;
        }

        $score = 0;
        $reasons = [];
        $signature = self::match_signatures($content);
        if ($signature) {
            $score += 10;
            $reasons[] = $signature;
        }

        $normalized_path = strtolower(ltrim($relative_path, '/'));
        $extension = strtolower(pathinfo($normalized_path, PATHINFO_EXTENSION));
        $is_php_payload = strpos($content, '<?php') !== false || strpos($content, '<?=') !== false;

        if (preg_match('/(?:auto_prepend_file|auto_append_file|php_value\s+auto_prepend_file|RewriteRule\s+.*https?:\/\/)/i', $content)) {
            $score += 7;
            $reasons[] = ['label' => 'Persistencia a nivel de servidor', 'desc' => 'Se detectó una directiva que puede inyectar código antes de cada petición o redirigir tráfico fuera del sitio.'];
        }

        // PHP under uploads/cache deserves review, but is not malware by itself.
        if ($is_php_payload && preg_match('#^wp-content/(uploads|cache|upgrade)/#', $normalized_path)) {
            $score += 1;
            $reasons[] = ['label' => 'PHP en directorio de contenido', 'desc' => 'La ruta merece revisión, pero no es una detección de malware por sí sola.'];
        }

        if ($is_php_payload && in_array($extension, ['phtml', 'pht', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8'], true)) {
            $score += 5;
            $reasons[] = ['label' => 'Extensión PHP alternativa', 'desc' => 'El archivo usa una extensión PHP alternativa, una técnica frecuente para evadir filtros de subida.'];
        }

        $obfuscators = preg_match_all('/\b(?:base64_decode|gzinflate|gzdecode|str_rot13|rawurldecode|urldecode)\s*\(/i', $content, $ignored);
        $plugin_persistence = preg_match('/(?:get_option|update_option)\s*\(\s*[\'\"]active_plugins[\'\"]|SELECT\s+.*?option_value\s+FROM\s+.*?options.*?active_plugins/is', $content);
        $direct_eval_payload = preg_match('/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzdecode|str_rot13|rawurldecode|urldecode|\$_(?:GET|POST|REQUEST|COOKIE))/i', $content);
        $direct_command_input = preg_match('/\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\([^;]{0,400}\$_(?:GET|POST|REQUEST|COOKIE)/is', $content);
        $encoded_file_write = preg_match('/\b(?:file_put_contents|fwrite)\s*\([^;]{0,500}(?:base64_decode|gzinflate|gzdecode|\$_(?:GET|POST|REQUEST|COOKIE))/is', $content);

        if ($direct_eval_payload || $direct_command_input) {
            $score += 8;
            $reasons[] = ['label' => 'Ejecución dinámica sospechosa', 'desc' => 'Se detectó ejecución directa de código o comandos a partir de entrada externa u ofuscación.'];
        }
        if ($obfuscators >= 3 && preg_match('/[A-Za-z0-9+\\/=_-]{600,}/', $content)) {
            $score += 3;
            $reasons[] = ['label' => 'Ofuscación encadenada', 'desc' => 'Se detectaron varias rutinas de codificación junto a un payload codificado extenso.'];
        }
        if ($encoded_file_write) {
            $score += 6;
            $reasons[] = ['label' => 'Escritura de payload sospechosa', 'desc' => 'Se detectó la escritura de un archivo a partir de contenido codificado o controlado externamente.'];
        }
        // WordPress core and legitimate plugins read active_plugins normally.
        // Treat it as suspicious only when it is coupled with an execution or
        // obfuscation signal, never as an IOC on its own.
        if ($plugin_persistence && ($direct_eval_payload || $direct_command_input || $encoded_file_write)) {
            $score += 3;
            $reasons[] = ['label' => 'Persistencia de plugins combinada', 'desc' => 'El archivo manipula plugins activos junto con ejecución, ofuscación o modificación de archivos.'];
        }

        if ($score < 7) {
            return null;
        }

        $primary = reset($reasons);
        return [
            'score' => $score,
            'label' => $score >= 10 ? $primary['label'] : 'Archivo altamente sospechoso',
            'desc'  => $primary['desc'] . ' Riesgo local: ' . $score . '/10.',
            'reasons' => $reasons,
        ];
    }

    /**
     * @param string $content
     * @return array|null
     */
    private static function match_signatures($content) {
        foreach (Signatures::get_signatures() as $signature) {
            if (@preg_match($signature['pattern'], $content)) {
                return ['label' => $signature['label'], 'desc' => $signature['desc']];
            }
        }

        return null;
    }
}
