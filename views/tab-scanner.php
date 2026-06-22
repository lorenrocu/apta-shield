<?php
defined('ABSPATH') || exit;
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Escáner de Virus e Integridad del Core', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Analiza la integridad de tus archivos locales contra las sumas de comprobación oficiales de WordPress.org y busca firmas de código malicioso.', 'apta-shield'); ?></p>
</div>

<div class="apta-card">
    <div class="card-header flex-header">
        <h3><?php esc_html_e('Analizador de Seguridad', 'apta-shield'); ?></h3>
        <button type="button" class="apta-btn apta-btn-success" id="apta-start-scan">
            <span class="dashicons dashicons-search icon-btn"></span>
            <?php esc_html_e('Iniciar Escaneo de Archivos', 'apta-shield'); ?>
        </button>
    </div>
    
    <div class="card-body">
        <!-- Scan Progress Console (Hidden by default) -->
        <div id="apta-scan-console" class="scan-console hidden">
            <div class="console-header">
                <span class="console-title"><?php esc_html_e('Progreso del Análisis...', 'apta-shield'); ?></span>
                <span class="console-percent" id="apta-scan-percent">0%</span>
            </div>
            <div class="progress-bar-wrap">
                <div class="progress-bar-inner" id="apta-scan-progress" style="width: 0%"></div>
            </div>
            <div class="console-logs" id="apta-scan-logs">
                <p class="log-info"><?php esc_html_e('Listo para iniciar...', 'apta-shield'); ?></p>
            </div>
        </div>

        <!-- Last Scan Stats -->
        <div id="apta-scan-results-summary" class="scan-results-summary <?php echo $last_scan === null ? 'hidden' : ''; ?>">
            <h4><?php esc_html_e('Resultados del Último Análisis', 'apta-shield'); ?></h4>
            <div class="results-grid">
                <div class="result-tile <?php echo (!empty($last_scan['core_modified_count'])) ? 'has-threats' : 'clean'; ?>">
                    <span class="dashicons <?php echo (!empty($last_scan['core_modified_count'])) ? 'dashicons-warning' : 'dashicons-yes'; ?>"></span>
                    <div class="tile-meta">
                        <span class="tile-num" id="apta-res-core-count"><?php echo !empty($last_scan['core_modified_count']) ? intval($last_scan['core_modified_count']) : 0; ?></span>
                        <span class="tile-label"><?php esc_html_e('Archivos del Core Modificados/Eliminados', 'apta-shield'); ?></span>
                    </div>
                </div>
                <div class="result-tile <?php echo (!empty($last_scan['malware_count'])) ? 'has-threats' : 'clean'; ?>">
                    <span class="dashicons <?php echo (!empty($last_scan['malware_count'])) ? 'dashicons-shield' : 'dashicons-yes'; ?>"></span>
                    <div class="tile-meta">
                        <span class="tile-num" id="apta-res-malware-count"><?php echo !empty($last_scan['malware_count']) ? intval($last_scan['malware_count']) : 0; ?></span>
                        <span class="tile-label"><?php esc_html_e('Firmas de Malware Detectadas', 'apta-shield'); ?></span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Results List -->
        <div id="apta-scan-details-list" class="scan-details-list <?php echo (empty($last_scan['threats'])) ? 'hidden' : ''; ?>">
            <h4><?php esc_html_e('Amenazas y Discrepancias Detectadas', 'apta-shield'); ?></h4>
            <div class="table-responsive">
                <table class="apta-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Archivo', 'apta-shield'); ?></th>
                            <th><?php esc_html_e('Tipo de Problema', 'apta-shield'); ?></th>
                            <th><?php esc_html_e('Descripción', 'apta-shield'); ?></th>
                            <th><?php esc_html_e('Acciones', 'apta-shield'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="apta-scan-tbody">
                        <?php 
                        if (!empty($last_scan['threats'])) {
                            foreach ($last_scan['threats'] as $index => $threat) {
                                echo '<tr id="apta-threat-row-' . esc_attr($index) . '">';
                                echo '<td><code>' . esc_html($threat['file']) . '</code></td>';
                                echo '<td><span class="badge badge-' . ($threat['type'] === 'malware' ? 'danger' : 'warning') . '">' . esc_html($threat['type_label']) . '</span></td>';
                                echo '<td>' . esc_html($threat['desc']) . '</td>';
                                echo '<td>';
                                if ($threat['type'] === 'core_modified') {
                                    echo '<span class="text-muted">' . esc_html__('Usa reinstalación', 'apta-shield') . '</span>';
                                } else {
                                    if (\AptaShield\Core\Plugin::is_pro_active()) {
                                        echo '<button type="button" class="apta-btn apta-btn-danger apta-btn-sm apta-clean-threat-btn" data-index="' . esc_attr($index) . '">' . esc_html__('Limpiar', 'apta-shield') . '</button>';
                                    } else {
                                        echo '<span class="badge badge-warning">' . esc_html__('Pro Only', 'apta-shield') . '</span>';
                                    }
                                }
                                echo '</td>';
                                echo '</tr>';
                            }
                        }
                        ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Core Reinstallation Panel -->
<div class="apta-card reinstaller-card">
    <div class="card-header">
        <h3><?php esc_html_e('Reinstalación Limpia del Núcleo (Core)', 'apta-shield'); ?></h3>
    </div>
    <div class="card-body">
        <p class="reinstall-description">
            <?php esc_html_e('Si tu sitio web ha sido comprometido o el escáner muestra múltiples archivos del core modificados por un atacante, puedes restaurar la integridad del sitio web de inmediato. Esta acción descargará una copia limpia oficial de tu versión de WordPress desde WordPress.org y reemplazará todos los archivos del core.', 'apta-shield'); ?>
        </p>
        
        <div class="warning-box warning-danger">
            <span class="dashicons dashicons-warning"></span>
            <div class="warning-content">
                <strong><?php esc_html_e('Información de Seguridad Importante', 'apta-shield'); ?></strong>
                <ul>
                    <li><?php esc_html_e('El plugin **NUNCA** modificará ni borrará tu carpeta `/wp-content/` (donde están tus plugins, temas y subidas).', 'apta-shield'); ?></li>
                    <li><?php esc_html_e('Tu archivo de configuración `wp-config.php` y archivos del servidor como `.htaccess` o `.user.ini` están completamente protegidos.', 'apta-shield'); ?></li>
                    <li><?php esc_html_e('Tus bases de datos no sufrirán ninguna modificación.', 'apta-shield'); ?></li>
                </ul>
            </div>
        </div>

        <div class="reinstall-actions">
            <div class="reinstall-meta">
                <span class="wp-version-label"><?php esc_html_e('Versión de WordPress detectada:', 'apta-shield'); ?></span>
                <strong class="wp-version-num"><?php echo esc_html($GLOBALS['wp_version']); ?></strong>
            </div>
            <button type="button" class="apta-btn apta-btn-danger" id="apta-run-reinstall">
                <span class="dashicons dashicons-update-alt icon-btn"></span>
                <?php esc_html_e('Reinstalar WordPress Core en 1-Clic', 'apta-shield'); ?>
            </button>
        </div>

        <div id="apta-reinstall-progress-box" class="reinstall-progress-box hidden">
            <div class="spinner-box">
                <span class="apta-spinner"></span>
                <span id="apta-reinstall-status-text"><?php esc_html_e('Descargando WordPress Core desde wordpress.org...', 'apta-shield'); ?></span>
            </div>
        </div>
    </div>
</div>
