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

    <!-- GeoIP Card (Pro) -->
    <div class="apta-card pro-feature-card">
        <div class="card-header flex-header">
            <h3><?php esc_html_e('Bloqueo por Países (GeoIP)', 'apta-shield'); ?></h3>
            <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
        </div>
        <div class="card-body">
            <p style="font-size: 13px; color: var(--apta-text-muted); line-height: 1.6; margin-top: 0;"><?php esc_html_e('Impide el acceso a todo el sitio web o a la pantalla de administración desde países de alto riesgo o regiones sospechosas utilizando la base de datos de MaxMind GeoIP.', 'apta-shield'); ?></p>
            
            <div style="background: rgba(248, 250, 252, 0.85); border: 1px dashed var(--apta-border); border-radius: var(--apta-radius-sm); padding: 16px; text-align: center; margin-top: 12px;">
                <span class="dashicons dashicons-location" style="font-size: 24px; width: 24px; height: 24px; color: var(--apta-danger); margin-bottom: 4px;"></span>
                <h4 style="font-size: 13px; font-weight: 700; margin: 0 0 2px 0;"><?php esc_html_e('Obtén Apta Shield Pro para bloquear por países', 'apta-shield'); ?></h4>
                <p style="font-size: 11px; color: var(--apta-text-muted); margin: 0;"><?php esc_html_e('Detén ataques de hackers masivos localizados geográficamente.', 'apta-shield'); ?></p>
            </div>
        </div>
    </div>
</div>

<!-- Rate Limiting Card (Pro) -->
<div class="apta-card pro-feature-card">
    <div class="card-header flex-header">
        <h3><?php esc_html_e('Limitación de Tasa Avanzada (Rate Limiting)', 'apta-shield'); ?></h3>
        <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
    </div>
    <div class="card-body">
        <p style="font-size: 13px; color: var(--apta-text-muted); line-height: 1.6; margin-top: 0;"><?php esc_html_e('Evita el raspado de datos (scrapers), ataques DDoS a páginas lentas e intentos de fuerza bruta sofisticados limitando el número máximo de peticiones por minuto por IP.', 'apta-shield'); ?></p>
        
        <div style="background: rgba(248, 250, 252, 0.85); border: 1px dashed var(--apta-border); border-radius: var(--apta-radius-sm); padding: 16px; text-align: center; margin-top: 12px;">
            <span class="dashicons dashicons-performance" style="font-size: 24px; width: 24px; height: 24px; color: var(--apta-danger); margin-bottom: 4px;"></span>
            <h4 style="font-size: 13px; font-weight: 700; margin: 0 0 2px 0;"><?php esc_html_e('Activa Rate Limiting con Apta Shield Pro', 'apta-shield'); ?></h4>
            <p style="font-size: 11px; color: var(--apta-text-muted); margin: 0;"><?php esc_html_e('Optimiza el uso de CPU de tu hosting controlando el tráfico abusivo.', 'apta-shield'); ?></p>
        </div>
    </div>
</div>

<!-- Active Bans Card -->
<div class="apta-card active-bans-card" style="margin-top: 24px;">
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
