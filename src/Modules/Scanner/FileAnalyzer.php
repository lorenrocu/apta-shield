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

        // PHP under uploads/cache is abnormal; combined with executable code is a strong signal.
        if ($is_php_payload && preg_match('#^wp-content/(uploads|cache|upgrade)/#', $normalized_path)) {
            $score += 7;
            $reasons[] = ['label' => 'PHP ejecutable en directorio de contenido', 'desc' => 'Se encontró código PHP en una ruta donde normalmente solo deberían existir archivos estáticos.'];
        }

        if ($is_php_payload && in_array($extension, ['phtml', 'pht', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8'], true)) {
            $score += 5;
            $reasons[] = ['label' => 'Extensión PHP alternativa', 'desc' => 'El archivo usa una extensión PHP alternativa, una técnica frecuente para evadir filtros de subida.'];
        }

        $dangerous_execution = preg_match_all('/\b(?:eval|assert|system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i', $content, $ignored);
        $dynamic_input = preg_match_all('/\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[/i', $content, $ignored);
        $obfuscators = preg_match_all('/\b(?:base64_decode|gzinflate|gzdecode|str_rot13|rawurldecode|urldecode)\s*\(/i', $content, $ignored);
        $file_mutation = preg_match_all('/\b(?:file_put_contents|fwrite|unlink|rename|copy|mkdir|chmod)\s*\(/i', $content, $ignored);
        $remote_access = preg_match_all('/\b(?:curl_exec|fsockopen|stream_socket_client|wp_remote_(?:get|post|request))\s*\(/i', $content, $ignored);

        if ($dangerous_execution && ($dynamic_input || $obfuscators)) {
            $score += 6;
            $reasons[] = ['label' => 'Ejecución dinámica sospechosa', 'desc' => 'Combina ejecución de código/comandos con entrada externa u ofuscación.'];
        }
        if ($obfuscators >= 2) {
            $score += 3;
            $reasons[] = ['label' => 'Ofuscación encadenada', 'desc' => 'Se detectaron varias rutinas de codificación o compresión en el mismo archivo.'];
        }
        if ($file_mutation && ($dangerous_execution || $obfuscators)) {
            $score += 3;
            $reasons[] = ['label' => 'Autopersistencia de archivos', 'desc' => 'El archivo puede modificar el sistema de archivos junto con ejecución u ofuscación.'];
        }
        if ($remote_access && ($dangerous_execution || $obfuscators)) {
            $score += 2;
            $reasons[] = ['label' => 'Canal remoto sospechoso', 'desc' => 'Combina acceso remoto con ejecución u ofuscación.'];
        }

        // Very long literals and a dense non-alphanumeric ratio are useful without attempting to decrypt anything.
        if (preg_match('/[A-Za-z0-9+\\/=_-]{600,}/', $content) && $obfuscators) {
            $score += 3;
            $reasons[] = ['label' => 'Payload codificado extenso', 'desc' => 'Se encontró una cadena codificada extensa junto a funciones de decodificación.'];
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
