<?php
defined('ABSPATH') || exit;
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if (!$wizard_completed) :
?>
    <!-- Onboarding Wizard Card -->
    <div class="apta-card apta-wizard-card" id="apta-wizard-container">
        <!-- Progress Steps -->
        <div class="wizard-steps-header">
            <div class="step-indicator active" data-step="1">
                <span class="step-num">1</span>
                <span class="step-label"><?php esc_html_e('Protección Core', 'apta-shield'); ?></span>
            </div>
            <div class="step-line"></div>
            <div class="step-indicator" data-step="2">
                <span class="step-num">2</span>
                <span class="step-label"><?php esc_html_e('Endurecimiento', 'apta-shield'); ?></span>
            </div>
            <div class="step-line"></div>
            <div class="step-indicator" data-step="3">
                <span class="step-num">3</span>
                <span class="step-label"><?php esc_html_e('Alertas', 'apta-shield'); ?></span>
            </div>
        </div>

        <div class="wizard-panes">
            <!-- Step 1 Pane -->
            <div class="wizard-pane active" id="wizard-step-1">
                <div class="wizard-pane-header">
                    <h2><?php esc_html_e('Protección Core Activa', 'apta-shield'); ?></h2>
                    <p><?php esc_html_e('Inicializa los motores principales de protección en tiempo real para tu WordPress.', 'apta-shield'); ?></p>
                </div>
                
                <div class="wizard-pane-body">
                    <!-- Firewall Toggle -->
                    <div class="wizard-field-group">
                        <div class="field-info">
                            <h3><?php esc_html_e('Web Application Firewall (WAF)', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Inspecciona todo el tráfico entrante para bloquear inyecciones SQL, scripts maliciosos (XSS), inclusión local de archivos (LFI) y ejecución remota de comandos (RCE).', 'apta-shield'); ?></p>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="firewall_enabled" value="1" <?php checked(1, $settings['firewall_enabled']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>

                    <!-- Brute Force Toggle -->
                    <div class="wizard-field-group border-top">
                        <div class="field-info">
                            <h3><?php esc_html_e('Protección contra Fuerza Bruta', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Monitorea los intentos fallidos de inicio de sesión y bloquea temporalmente a las direcciones IP sospechosas para proteger tus cuentas.', 'apta-shield'); ?></p>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="brute_force_enabled" value="1" <?php checked(1, $settings['brute_force_enabled']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>
                </div>

                <div class="wizard-pane-footer">
                    <div></div>
                    <button type="button" class="apta-btn apta-btn-primary btn-wizard-next">
                        <?php esc_html_e('Siguiente Paso', 'apta-shield'); ?> <span class="dashicons dashicons-arrow-right-alt2"></span>
                    </button>
                </div>
            </div>

            <!-- Step 2 Pane -->
            <div class="wizard-pane" id="wizard-step-2">
                <div class="wizard-pane-header">
                    <h2><?php esc_html_e('Endurecimiento y Privacidad', 'apta-shield'); ?></h2>
                    <p><?php esc_html_e('Ajusta políticas internas y esconde rutas críticas para mitigar el escaneo automático de bots.', 'apta-shield'); ?></p>
                </div>

                <div class="wizard-pane-body">
                    <!-- XML-RPC Toggle -->
                    <div class="wizard-field-group">
                        <div class="field-info">
                            <h3><?php esc_html_e('Desactivar XML-RPC', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Deshabilita el protocolo xmlrpc.php, usado con frecuencia para explotar ataques de fuerza bruta multihilo o DDoS.', 'apta-shield'); ?></p>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="hardening_xmlrpc" value="1" <?php checked(1, $settings['hardening_xmlrpc']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>

                    <!-- File Edit Toggle -->
                    <div class="wizard-field-group border-top">
                        <div class="field-info">
                            <h3><?php esc_html_e('Desactivar Editor de Archivos', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Previene que administradores del sitio editen código PHP directamente desde el panel de WordPress (seguridad en caso de compromiso de sesión).', 'apta-shield'); ?></p>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="hardening_file_edit" value="1" <?php checked(1, $settings['hardening_file_edit']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>

                    <!-- Hide WP Version / Author Scan Toggles -->
                    <div class="wizard-field-group border-top">
                        <div class="field-info">
                            <h3><?php esc_html_e('Ocultar Versión de WordPress', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Elimina la información pública sobre la versión actual del CMS de la cabecera del sitio.', 'apta-shield'); ?></p>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="hardening_wp_version" value="1" <?php checked(1, $settings['hardening_wp_version']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>

                    <div class="wizard-field-group border-top">
                        <div class="field-info">
                            <h3><?php esc_html_e('Bloquear Enumeración de Usuarios', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Bloquea las peticiones que intenten listar los nombres de usuarios del sitio mediante las URL de autor.', 'apta-shield'); ?></p>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="hardening_author_scan" value="1" <?php checked(1, $settings['hardening_author_scan']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>

                    <!-- Obfuscator Toggle -->
                    <div class="wizard-field-group border-top">
                        <div class="field-info">
                            <h3><?php esc_html_e('Ocultar URL de Inicio de Sesión', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Oculta wp-login.php y wp-admin tras una URL secreta. Muy recomendado para frenar de golpe ataques automatizados.', 'apta-shield'); ?></p>
                            
                            <div class="wizard-subfield hidden" id="wizard-obfuscator-sub">
                                <label for="wizard_url_slug" class="form-label"><?php esc_html_e('Slug de Acceso Personalizado:', 'apta-shield'); ?></label>
                                <div class="apta-input-prefix-wrapper">
                                    <span class="input-prefix"><?php echo esc_url(home_url('/')); ?></span>
                                    <input type="text" id="wizard_url_slug" name="url_obfuscator_slug" class="apta-input" value="<?php echo esc_attr($settings['url_obfuscator_slug']); ?>" placeholder="mi-login-secreto">
                                </div>
                                <span class="field-desc"><?php esc_html_e('Solo letras, números y guiones. ¡Guarda bien esta dirección!', 'apta-shield'); ?></span>
                            </div>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="url_obfuscator_enabled" id="wizard_url_obfuscator_enabled" value="1" <?php checked(1, $settings['url_obfuscator_enabled']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>
                </div>

                <div class="wizard-pane-footer">
                    <button type="button" class="apta-btn apta-btn-secondary btn-wizard-prev">
                        <span class="dashicons dashicons-arrow-left-alt2"></span> <?php esc_html_e('Atrás', 'apta-shield'); ?>
                    </button>
                    <button type="button" class="apta-btn apta-btn-primary btn-wizard-next">
                        <?php esc_html_e('Siguiente Paso', 'apta-shield'); ?> <span class="dashicons dashicons-arrow-right-alt2"></span>
                    </button>
                </div>
            </div>

            <!-- Step 3 Pane -->
            <div class="wizard-pane" id="wizard-step-3">
                <div class="wizard-pane-header">
                    <h2><?php esc_html_e('Alertas y Notificaciones', 'apta-shield'); ?></h2>
                    <p><?php esc_html_e('Especifica dónde quieres recibir los informes de eventos críticos y de hackeo.', 'apta-shield'); ?></p>
                </div>

                <div class="wizard-pane-body">
                    <!-- Email Alerts Toggle -->
                    <div class="wizard-field-group">
                        <div class="field-info">
                            <h3><?php esc_html_e('Activar Alertas Inmediatas por Correo', 'apta-shield'); ?></h3>
                            <p><?php esc_html_e('Recibe correos electrónicos detallados de inmediato si la protección detecta malware, hackeos o IPs intentando asaltar el sitio.', 'apta-shield'); ?></p>
                            
                            <div class="wizard-subfield" id="wizard-notifier-sub">
                                <label for="wizard_notifier_email" class="form-label"><?php esc_html_e('Dirección de Destino:', 'apta-shield'); ?></label>
                                <input type="email" id="wizard_notifier_email" name="notifier_email" class="apta-input" value="<?php echo esc_attr($settings['notifier_email']); ?>" placeholder="admin@tusitio.com" style="max-width: 100%;">
                            </div>
                        </div>
                        <label class="apta-switch">
                            <input type="checkbox" name="notifier_enabled" id="wizard_notifier_enabled" value="1" <?php checked(1, $settings['notifier_enabled']); ?>>
                            <span class="slider round"></span>
                        </label>
                    </div>
                </div>

                <div class="wizard-pane-footer">
                    <button type="button" class="apta-btn apta-btn-secondary btn-wizard-prev">
                        <span class="dashicons dashicons-arrow-left-alt2"></span> <?php esc_html_e('Atrás', 'apta-shield'); ?>
                    </button>
                    <button type="button" class="apta-btn apta-btn-success" id="apta-wizard-complete-btn">
                        <?php esc_html_e('Finalizar Configuración', 'apta-shield'); ?> <span class="dashicons dashicons-yes-alt"></span>
                    </button>
                </div>
            </div>

            <!-- Success Pane -->
            <div class="wizard-pane text-center" id="wizard-step-success">
                <div class="success-icon-area">
                    <span class="dashicons dashicons-yes-alt anim-pulse"></span>
                </div>
                <h2><?php esc_html_e('¡Tu sitio ya está blindado!', 'apta-shield'); ?></h2>
                <p class="success-desc"><?php esc_html_e('Hemos guardado tus preferencias y activado las capas esenciales de seguridad. Tu sitio web ahora tiene un escudo protector activo contra ataques.', 'apta-shield'); ?></p>
                
                <div class="success-summary-box">
                    <h4><?php esc_html_e('Resumen de Protección Activa:', 'apta-shield'); ?></h4>
                    <ul class="success-summary-list">
                        <li><span class="dashicons dashicons-yes text-success"></span> <?php esc_html_e('Firewall Web activo contra amenazas principales.', 'apta-shield'); ?></li>
                        <li><span class="dashicons dashicons-yes text-success"></span> <?php esc_html_e('Fuerza Bruta bloqueando IPs atacantes.', 'apta-shield'); ?></li>
                        <li><span class="dashicons dashicons-yes text-success"></span> <?php esc_html_e('Cabeceras de protección HTTP y optimizaciones.', 'apta-shield'); ?></li>
                    </ul>
                </div>

                <button type="button" class="apta-btn apta-btn-primary btn-large" id="apta-wizard-enter-dashboard">
                    <?php esc_html_e('Ir al Panel de Control', 'apta-shield'); ?>
                </button>
            </div>
        </div>
    </div>
<?php
else :
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
<?php
endif;
?>
