<?php

namespace AptaShield\Modules\Scanner;

defined('ABSPATH') || exit;

/**
 * Class Signatures
 * Holds malware signature regexes and descriptions.
 */
class Signatures {

    /**
     * Get array of malware signatures.
     *
     * @return array
     */
    public static function get_signatures() {
        return [
            [
                'id'      => 'vapor_worker_io_mu_backdoor',
                'pattern' => '/Plugin\s+Name\s*:\s*Vapor\s+Worker\s+IO|Text\s+Domain\s*:\s*vapor-worker-io/i',
                'label'   => __('Backdoor persistente en mu-plugin', 'apta-shield'),
                'desc'    => __('Detectada la familia Vapor Worker IO: un mu-plugin ofuscado que se carga automáticamente y mantiene persistencia.', 'apta-shield')
            ],
            [
                'id'      => 'indexed_string_table_obfuscation',
                'pattern' => '/function\s+[a-z_][a-z0-9_]*\s*\(\s*\$[a-z_][a-z0-9_]*\s*\)\s*\{\s*static\s+\$[a-z_][a-z0-9_]*\s*=\s*null\s*;.*?\$[a-z_][a-z0-9_]*\s*=\s*array\s*\(.*?return\s+\$[a-z_][a-z0-9_]*\s*\[\s*\$[a-z_][a-z0-9_]*\s*\]\s*;/is',
                'label'   => __('Ofuscación mediante tabla de cadenas', 'apta-shield'),
                'desc'    => __('Detectado un decodificador indexado de cadenas, una técnica usada para ocultar llamadas peligrosas en backdoors PHP.', 'apta-shield')
            ],
            [
                'id'      => 'plugin_persistence_manipulation',
                'pattern' => '/(?:get_option|update_option)\s*\(\s*[\'\"]active_plugins[\'\"]|SELECT\s+.*?option_value\s+FROM\s+.*?options.*?active_plugins/is',
                'label'   => __('Manipulación de persistencia de plugins', 'apta-shield'),
                'desc'    => __('Detectado código que lee o altera la lista de plugins activos, un comportamiento típico de malware persistente.', 'apta-shield')
            ],
            [
                'id'      => 'eval_base64',
                'pattern' => '/eval\s*\(\s*base64_decode\s*\(/i',
                'label'   => __('Codificación sospechosa (base64)', 'apta-shield'),
                'desc'    => __('Encontrado patrón eval(base64_decode) utilizado comúnmente para ejecutar código malicioso ofuscado.', 'apta-shield')
            ],
            [
                'id'      => 'gzinflate_base64',
                'pattern' => '/(eval|assert)\s*\(\s*gz(inflate|uncompress|decode)\s*\(\s*base64_decode/i',
                'label'   => __('Compresión y ofuscación sospechosa', 'apta-shield'),
                'desc'    => __('Detectado uso de compresión gzip más base64_decode, un método clásico de webshells PHP.', 'apta-shield')
            ],
            [
                'id'      => 'known_webshells',
                'pattern' => '/c99shell|r57shell|wso_version|filesman|phpspy|cyberwarrior/i',
                'label'   => __('WebShell conocida', 'apta-shield'),
                'desc'    => __('Detectados términos correspondientes a WebShells maliciosas populares.', 'apta-shield')
            ],
            [
                'id'      => 'backdoor_payload',
                'pattern' => '/\$_(GET|POST|REQUEST)\[.*?\]\s*\(\s*\$_(GET|POST|REQUEST)/i',
                'label'   => __('Backdoor dinámica (RCE)', 'apta-shield'),
                'desc'    => __('Detectado patrón de ejecución dinámica a través de parámetros globales (ej. $_POST[x]($_POST[y])).', 'apta-shield')
            ],
            [
                'id'      => 'javascript_injection',
                'pattern' => '/<script[^>]*src=["\']http[s]?:\/\/[a-z0-9\-]+\.[a-z0-9\-]+\.[a-z]{2,5}\/[a-z0-9\-]+\.js/i',
                'label'   => __('Script externo inyectado', 'apta-shield'),
                'desc'    => __('Detección de enlaces sospechosos a scripts JavaScript externos inyectados directamente en código PHP.', 'apta-shield')
            ],
            [
                'id'      => 'file_put_contents_backdoor',
                'pattern' => '/file_put_contents\s*\(\s*[\'"][^\'"]+\.php[\'"]\s*,\s*base64_decode/i',
                'label'   => __('Creación de archivos PHP maliciosos', 'apta-shield'),
                'desc'    => __('Estructura sospechosa que intenta escribir un nuevo archivo .php decodificando base64.', 'apta-shield')
            ]
        ];
    }
}
