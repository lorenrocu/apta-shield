<?php
defined('ABSPATH') || exit;
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Resumen de Seguridad', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Vista rápida del estado de protección de tu sitio web.', 'apta-shield'); ?></p>
</div>

<div class="apta-grid grid-2">
    <!-- Health Score Card -->
    <div class="apta-card health-score-card">
        <div class="card-header">
            <h3><?php esc_html_e('Salud del Sitio', 'apta-shield'); ?></h3>
        </div>
        <div class="card-body gauge-container">
            <div class="apta-gauge">
                <svg viewBox="0 0 36 36" class="circular-chart <?php echo $score >= 75 ? 'green' : ($score >= 50 ? 'orange' : 'red'); ?>">
                    <path class="circle-bg"
                        d="M18 2.0845
                            a 15.9155 15.9155 0 0 1 0 31.831
                            a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    <path class="circle"
                        stroke-dasharray="<?php echo esc_attr($score); ?>, 100"
                        d="M18 2.0845
                            a 15.9155 15.9155 0 0 1 0 31.831
                            a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    <text x="18" y="20.35" class="percentage"><?php echo esc_html($score); ?>%</text>
                </svg>
            </div>
            <div class="gauge-meta">
                <h4>
                    <?php 
                    if ($score >= 100) {
                        esc_html_e('¡Excelente protección!', 'apta-shield');
                    } elseif ($score >= 75) {
                        esc_html_e('Protección activa adecuada', 'apta-shield');
                    } elseif ($score >= 50) {
                        esc_html_e('Nivel de seguridad medio', 'apta-shield');
                    } else {
                        esc_html_e('¡Tu sitio está expuesto!', 'apta-shield');
                    }
                    ?>
                </h4>
                <p><?php esc_html_e('Activa más módulos de seguridad para aumentar tu puntuación.', 'apta-shield'); ?></p>
            </div>
        </div>
    </div>

    <!-- Quick Stats Card -->
    <div class="apta-card quick-stats-card">
        <div class="card-header">
            <h3><?php esc_html_e('Estadísticas en Tiempo Real', 'apta-shield'); ?></h3>
        </div>
        <div class="card-body stats-grid">
            <div class="stat-box">
                <span class="stat-number"><?php echo esc_html($total_blocked); ?></span>
                <span class="stat-label"><?php esc_html_e('Ataques Bloqueados', 'apta-shield'); ?></span>
            </div>
            <div class="stat-box">
                <span class="stat-number"><?php echo esc_html($active_bans); ?></span>
                <span class="stat-label"><?php esc_html_e('IPs Bloqueadas Activas', 'apta-shield'); ?></span>
            </div>
            <div class="stat-box full-width">
                <span class="stat-label"><?php esc_html_e('Último Análisis', 'apta-shield'); ?></span>
                <span class="stat-value">
                    <?php 
                    if ($last_scan !== null) {
                        $time_diff = human_time_diff($last_scan['time'], time());
                        // translators: %s: Time elapsed since the last scan (e.g. 5 minutes).
                        printf(esc_html__('Hace %s', 'apta-shield'), esc_html($time_diff));
                        echo ' - ';
                        if ($last_scan['malware_count'] > 0 || $last_scan['core_modified_count'] > 0) {
                            // translators: %d: Total number of security threats found.
                            echo '<span class="text-danger font-bold">' . esc_html(sprintf(__('%d Amenazas encontradas', 'apta-shield'), $last_scan['malware_count'] + $last_scan['core_modified_count'])) . '</span>';
                        } else {
                            echo '<span class="text-success font-bold">' . esc_html(__('Limpio', 'apta-shield')) . '</span>';
                        }
                    } else {
                        esc_html_e('Nunca se ha realizado un análisis.', 'apta-shield');
                    }
                    ?>
                </span>
            </div>
        </div>
    </div>
</div>

<!-- Recommendations Card -->
<div class="apta-card recommendations-card">
    <div class="card-header">
        <h3><?php esc_html_e('Recomendaciones de Seguridad', 'apta-shield'); ?></h3>
    </div>
    <div class="card-body">
        <ul class="recommendations-list">
            <?php if (!$settings['firewall_enabled']): ?>
                <li class="reco-item reco-warning">
                    <span class="dashicons dashicons-warning"></span>
                    <div class="reco-content">
                        <strong><?php esc_html_e('El Firewall (WAF) está desactivado', 'apta-shield'); ?></strong>
                        <p><?php esc_html_e('Activa el Firewall para mitigar intentos de inyección SQL, ataques XSS y scripts maliciosos antes de que dañen tu sitio.', 'apta-shield'); ?></p>
                    </div>
                </li>
            <?php endif; ?>

            <?php if (!$settings['brute_force_enabled']): ?>
                <li class="reco-item reco-warning">
                    <span class="dashicons dashicons-warning"></span>
                    <div class="reco-content">
                        <strong><?php esc_html_e('La protección de Fuerza Bruta está desactivada', 'apta-shield'); ?></strong>
                        <p><?php esc_html_e('Sin este módulo, los bots atacantes pueden intentar adivinar contraseñas repetidamente sin restricciones.', 'apta-shield'); ?></p>
                    </div>
                </li>
            <?php endif; ?>

            <?php if (!$settings['url_obfuscator_enabled']): ?>
                <li class="reco-item reco-info">
                    <span class="dashicons dashicons-info"></span>
                    <div class="reco-content">
                        <strong><?php esc_html_e('Tu URL de inicio de sesión es pública', 'apta-shield'); ?></strong>
                        <p><?php esc_html_e('Cualquiera puede acceder a wp-login.php. Habilita "Ocultar URL" para ocultar tu página de login con un slug secreto.', 'apta-shield'); ?></p>
                    </div>
                </li>
            <?php endif; ?>

            <?php if ($last_scan === null): ?>
                <li class="reco-item reco-info">
                    <span class="dashicons dashicons-info"></span>
                    <div class="reco-content">
                        <strong><?php esc_html_e('Realiza tu primer análisis de virus', 'apta-shield'); ?></strong>
                        <p><?php esc_html_e('Te recomendamos hacer un análisis inicial para verificar la integridad del núcleo de WordPress y detectar scripts sospechosos.', 'apta-shield'); ?></p>
                    </div>
                </li>
            <?php elseif ($last_scan['malware_count'] > 0 || $last_scan['core_modified_count'] > 0): ?>
                <li class="reco-item reco-danger">
                    <span class="dashicons dashicons-dismiss"></span>
                    <div class="reco-content">
                        <strong><?php esc_html_e('¡Tu sitio contiene archivos comprometidos!', 'apta-shield'); ?></strong>
                        <p><?php esc_html_e('El último escaneo encontró discrepancias en el core o patrones de código malicioso. Ejecuta la reinstalación del core o limpia los archivos indicados.', 'apta-shield'); ?></p>
                    </div>
                </li>
            <?php endif; ?>

            <?php if ($settings['firewall_enabled'] && $settings['brute_force_enabled'] && $settings['url_obfuscator_enabled'] && $last_scan !== null && $last_scan['malware_count'] == 0 && $last_scan['core_modified_count'] == 0): ?>
                <li class="reco-item reco-success">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <div class="reco-content">
                        <strong><?php esc_html_e('¡Buen trabajo! Tu sitio está completamente configurado y protegido', 'apta-shield'); ?></strong>
                        <p><?php esc_html_e('Todos los módulos clave están activos y no se han encontrado virus o archivos alterados.', 'apta-shield'); ?></p>
                    </div>
                </li>
            <?php endif; ?>
        </ul>
    </div>
</div>
