<?php
defined('ABSPATH') || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

// Render the trusted proxies list as one entry per line, joined by newlines.
$trusted_proxies_value = '';
if (!empty($settings['trusted_proxies']) && is_array($settings['trusted_proxies'])) {
    $trusted_proxies_value = implode("\n", $settings['trusted_proxies']);
}
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Endurecimiento del Sitio (Hardening)', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Desactiva características débiles por defecto e inyecta directivas de seguridad para reducir la superficie de ataque.', 'apta-shield'); ?></p>
</div>

<div class="apta-card">
    <div class="card-header">
        <h3><?php esc_html_e('Reglas de Endurecimiento Crítico', 'apta-shield'); ?></h3>
    </div>
    
    <div class="card-body">
        <!-- Disallow File Edit -->
        <div class="apta-form-group toggle-group">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Desactivar editor de código nativo', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Desactiva el editor integrado de temas y plugins de WordPress. Evita que un hacker que consiga credenciales de administrador inyecte malware desde el panel.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="hardening_file_edit" value="1" <?php checked(1, $settings['hardening_file_edit']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <!-- Disable XML-RPC -->
        <div class="apta-form-group toggle-group border-top">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Desactivar protocolo XML-RPC', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Bloquea el acceso a xmlrpc.php. XML-RPC es un protocolo antiguo usado a menudo para ataques masivos de fuerza bruta y DDoS.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="hardening_xmlrpc" value="1" <?php checked(1, $settings['hardening_xmlrpc']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <!-- Block Author Enumeration -->
        <div class="apta-form-group toggle-group border-top">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Bloquear enumeración de autores/usuarios', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Previene peticiones de bots a través de "?author=N" que revelan los nombres de usuario del sitio para ataques de fuerza bruta dirigidos.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="hardening_author_scan" value="1" <?php checked(1, $settings['hardening_author_scan']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <!-- Hide WP Version -->
        <div class="apta-form-group toggle-group border-top">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Ocultar versión de WordPress', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Elimina la etiqueta generadora HTML y los parámetros de versión de los enlaces a estilos CSS y scripts JS de tu web, impidiendo que escáneres detecten versiones vulnerables.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="hardening_wp_version" value="1" <?php checked(1, $settings['hardening_wp_version']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>
    </div>
</div>

<div class="apta-card">
    <div class="card-header">
        <h3><?php esc_html_e('Seguridad del Servidor y Cabeceras HTTP', 'apta-shield'); ?></h3>
    </div>
    
    <div class="card-body">
        <!-- HTTP Security Headers -->
        <div class="apta-form-group toggle-group">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Inyectar Cabeceras de Seguridad HTTP', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Añade automáticamente las cabeceras estándar de protección de navegador: X-Frame-Options (SAMEORIGIN), X-Content-Type-Options (nosniff), X-XSS-Protection (1; mode=block) y Referrer-Policy.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="hardening_headers" value="1" <?php checked(1, $settings['hardening_headers']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <div class="info-note">
            <span class="dashicons dashicons-external"></span>
            <p><?php esc_html_e('Las cabeceras se inyectan dinámicamente en cada carga de página. Al activarlas, proteges a tus visitantes contra clickjacking, secuestros de frames y ejecución de archivos simulados.', 'apta-shield'); ?></p>
        </div>
    </div>
</div>

<!-- Trusted Proxies (anti-spoofing for X-Forwarded-For) -->
<div class="apta-card">
    <div class="card-header">
        <h3><?php esc_html_e('Proxies de Confianza (Anti-Spoofing de IP)', 'apta-shield'); ?></h3>
    </div>

    <div class="card-body">
        <p class="reinstall-description">
            <?php esc_html_e('Por defecto, Apta Shield ignora completamente la cabecera HTTP X-Forwarded-For para evitar que cualquier atacante suplante su IP. Si tu sitio está detrás de un proxy inverso, CDN o load balancer que sí reenvía la IP real del cliente, agrega aquí su IP o rango CIDR. Una entrada por línea.', 'apta-shield'); ?>
        </p>

        <div class="apta-form-group">
            <label for="trusted_proxies" class="form-label"><?php esc_html_e('IPs o rangos CIDR de proxies de confianza', 'apta-shield'); ?></label>
            <textarea
                id="trusted_proxies"
                name="trusted_proxies"
                class="apta-input settings-trigger"
                rows="6"
                style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px;"
                placeholder="173.245.48.0/20&#10;103.21.244.0/22&#10;10.0.0.0/8"
            ><?php echo esc_textarea($trusted_proxies_value); ?></textarea>
            <span class="field-desc">
                <?php esc_html_e('Una entrada por línea. Acepta IPs individuales (192.168.1.10) o rangos CIDR (10.0.0.0/8, 2001:db8::/32). Si lo dejas vacío, X-Forwarded-For se ignora y se usa la IP de la conexión TCP directamente — la opción más segura.', 'apta-shield'); ?>
            </span>
        </div>

        <div class="info-note">
            <span class="dashicons dashicons-info"></span>
            <p>
                <strong><?php esc_html_e('Proveedores comunes:', 'apta-shield'); ?></strong><br>
                Cloudflare: 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22<br>
                Sucuri: 192.88.134.0/23, 185.93.228.0/22<br>
                <?php esc_html_e('Consulta la lista actualizada en la documentación de tu proveedor.', 'apta-shield'); ?>
            </p>
        </div>
    </div>
</div>
