<?php
defined('ABSPATH') || exit;
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Ajustes Generales y Alertas', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Configura las alertas de seguridad por correo electrónico y el comportamiento del análisis automatizado.', 'apta-shield'); ?></p>
</div>

<div class="apta-card">
    <div class="card-header">
        <h3><?php esc_html_e('Automatización de Escaneos y Auto-Recuperación', 'apta-shield'); ?></h3>
    </div>
    <div class="card-body">
        <!-- Auto Scan Toggle -->
        <div class="apta-form-group toggle-group">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Análisis Diario Automatizado', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Ejecuta un escaneo silencioso en segundo plano cada 24 horas usando WP-Cron.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="scanner_auto_scan" value="1" <?php checked(1, $settings['scanner_auto_scan']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <!-- Auto Recovery Toggle -->
        <div class="apta-form-group toggle-group border-top">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Auto-Recuperación del Core Comprometido', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Si el escaneo automático detecta archivos del núcleo de WordPress modificados o corruptos, descarga y reinstala automáticamente los archivos del núcleo limpios.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="scanner_auto_recovery" value="1" <?php checked(1, $settings['scanner_auto_recovery']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>
    </div>
</div>

<div class="apta-card">
    <div class="card-header">
        <h3><?php esc_html_e('Alertas por Correo Electrónico', 'apta-shield'); ?></h3>
    </div>
    <div class="card-body">
        <!-- Email Alert Toggle -->
        <div class="apta-form-group toggle-group">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Activar Alertas por Email', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Envía notificaciones de alerta inmediata al administrador si se detecta virus, bloqueos masivos o re-instalaciones autónomas.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="notifier_enabled" value="1" <?php checked(1, $settings['notifier_enabled']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <div class="apta-settings-subfields <?php echo !$settings['notifier_enabled'] ? 'disabled-section' : ''; ?>" id="notifier-subfields">
            <div class="apta-form-group">
                <label for="notifier_email" class="form-label"><?php esc_html_e('Destinatario de Alertas', 'apta-shield'); ?></label>
                <input type="email" id="notifier_email" name="notifier_email" class="apta-input settings-trigger" value="<?php echo esc_attr($settings['notifier_email']); ?>" placeholder="admin@tusitio.com">
                <span class="field-desc"><?php esc_html_e('Dirección de correo electrónico donde se enviarán los reportes de seguridad críticos.', 'apta-shield'); ?></span>
            </div>
        </div>
    </div>
</div>
