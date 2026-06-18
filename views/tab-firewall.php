<?php
defined('ABSPATH') || exit;
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Firewall (WAF) y Fuerza Bruta', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Protege tu sitio de ataques HTTP maliciosos, inyecciones de código y adivinación de contraseñas mediante fuerza bruta.', 'apta-shield'); ?></p>
</div>

<div class="apta-grid grid-2">
    <!-- WAF Card -->
    <div class="apta-card">
        <div class="card-header">
            <h3><?php esc_html_e('Cortafuegos (WAF) Básico', 'apta-shield'); ?></h3>
        </div>
        <div class="card-body">
            <div class="apta-form-group toggle-group">
                <div class="toggle-meta">
                    <label class="toggle-title"><?php esc_html_e('Activar Firewall (WAF)', 'apta-shield'); ?></label>
                    <span class="toggle-desc"><?php esc_html_e('Inspecciona peticiones entrantes ($_GET, $_POST) buscando inyecciones SQL (SQLi), Cross-Site Scripting (XSS) y ejecución de código.', 'apta-shield'); ?></span>
                </div>
                <label class="apta-switch">
                    <input type="checkbox" name="firewall_enabled" value="1" <?php checked(1, $settings['firewall_enabled']); ?> class="settings-trigger">
                    <span class="slider round"></span>
                </label>
            </div>
            
            <div class="info-note">
                <span class="dashicons dashicons-shield"></span>
                <p><?php esc_html_e('El firewall actúa de forma autónoma. Si se detecta un patrón malicioso en la URL o el formulario, el atacante recibirá una pantalla 403 de acceso prohibido.', 'apta-shield'); ?></p>
            </div>
        </div>
    </div>

    <!-- Brute Force Card -->
    <div class="apta-card">
        <div class="card-header">
            <h3><?php esc_html_e('Protección contra Fuerza Bruta', 'apta-shield'); ?></h3>
        </div>
        <div class="card-body">
            <div class="apta-form-group toggle-group">
                <div class="toggle-meta">
                    <label class="toggle-title"><?php esc_html_e('Activar Protección de Acceso', 'apta-shield'); ?></label>
                    <span class="toggle-desc"><?php esc_html_e('Monitorea intentos de login fallidos y bloquea temporalmente las direcciones IP sospechosas.', 'apta-shield'); ?></span>
                </div>
                <label class="apta-switch">
                    <input type="checkbox" name="brute_force_enabled" value="1" <?php checked(1, $settings['brute_force_enabled']); ?> class="settings-trigger">
                    <span class="slider round"></span>
                </label>
            </div>

            <div class="apta-settings-subfields <?php echo !$settings['brute_force_enabled'] ? 'disabled-section' : ''; ?>" id="brute-force-subfields">
                <div class="apta-form-group">
                    <label for="brute_force_max_attempts" class="form-label"><?php esc_html_e('Intentos de login permitidos', 'apta-shield'); ?></label>
                    <input type="number" id="brute_force_max_attempts" name="brute_force_max_attempts" min="1" max="20" class="apta-input settings-trigger" value="<?php echo esc_attr($settings['brute_force_max_attempts']); ?>">
                    <span class="field-desc"><?php esc_html_e('Número de intentos de acceso fallidos antes de bloquear la IP.', 'apta-shield'); ?></span>
                </div>

                <div class="apta-form-group">
                    <label for="brute_force_lockout_duration" class="form-label"><?php esc_html_e('Duración del bloqueo (Minutos)', 'apta-shield'); ?></label>
                    <input type="number" id="brute_force_lockout_duration" name="brute_force_lockout_duration" min="5" max="1440" class="apta-input settings-trigger" value="<?php echo esc_attr($settings['brute_force_lockout_duration']); ?>">
                    <span class="field-desc"><?php esc_html_e('Tiempo en minutos que la IP sospechosa tendrá denegado el acceso al sitio.', 'apta-shield'); ?></span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Active Bans Card -->
<div class="apta-card active-bans-card">
    <div class="card-header flex-header">
        <h3><?php esc_html_e('Direcciones IP Bloqueadas', 'apta-shield'); ?></h3>
        <button type="button" class="apta-btn apta-btn-secondary" id="apta-refresh-bans">
            <span class="dashicons dashicons-update icon-btn"></span>
            <?php esc_html_e('Actualizar Lista', 'apta-shield'); ?>
        </button>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="apta-table">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Dirección IP', 'apta-shield'); ?></th>
                        <th><?php esc_html_e('Razón del Bloqueo', 'apta-shield'); ?></th>
                        <th><?php esc_html_e('Bloqueada En', 'apta-shield'); ?></th>
                        <th><?php esc_html_e('Bloqueada Hasta', 'apta-shield'); ?></th>
                        <th><?php esc_html_e('Acción', 'apta-shield'); ?></th>
                    </tr>
                </thead>
                <tbody id="apta-bans-tbody">
                    <!-- Banned IPs will be populated by AJAX -->
                    <tr class="apta-loading-row">
                        <td colspan="5" style="text-align: center;">
                            <span class="apta-spinner"></span> <?php esc_html_e('Cargando registros...', 'apta-shield'); ?>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
