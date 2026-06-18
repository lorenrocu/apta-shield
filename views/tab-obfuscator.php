<?php
defined('ABSPATH') || exit;
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Ocultar URL de Administración y Acceso', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Previene ataques automatizados de adivinación de contraseñas ocultando los accesos nativos de WordPress (wp-login.php y wp-admin) tras una URL secreta.', 'apta-shield'); ?></p>
</div>

<div class="apta-card">
    <div class="card-header">
        <h3><?php esc_html_e('Configuración de URL Personalizada', 'apta-shield'); ?></h3>
    </div>
    <div class="card-body">
        <div class="apta-form-group toggle-group">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Activar Ofuscación de URL', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Bloquea wp-login.php y redirige a los usuarios no autenticados que intentan entrar a wp-admin a una página de no encontrado (404).', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="url_obfuscator_enabled" id="url_obfuscator_enabled" value="1" <?php checked(1, $settings['url_obfuscator_enabled']); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <div class="apta-settings-subfields <?php echo !$settings['url_obfuscator_enabled'] ? 'disabled-section' : ''; ?>" id="url-obfuscator-subfields">
            <div class="apta-form-group">
                <label for="url_obfuscator_slug" class="form-label"><?php esc_html_e('Slug de Acceso Secreto', 'apta-shield'); ?></label>
                <div class="apta-input-prefix-wrapper">
                    <span class="input-prefix"><?php echo esc_url(home_url('/')); ?></span>
                    <input type="text" id="url_obfuscator_slug" name="url_obfuscator_slug" class="apta-input settings-trigger" value="<?php echo esc_attr($settings['url_obfuscator_slug']); ?>" placeholder="mi-login-secreto">
                </div>
                <span class="field-desc"><?php esc_html_e('Usa un slug fácil de recordar pero difícil de adivinar. Solo caracteres alfanuméricos y guiones.', 'apta-shield'); ?></span>
            </div>

            <!-- Live URL Preview -->
            <div class="apta-live-url-preview">
                <h4><?php esc_html_e('Tu URL de inicio de sesión actual:', 'apta-shield'); ?></h4>
                <div class="url-preview-box">
                    <code id="apta-preview-link"><?php echo esc_url(home_url('/' . $settings['url_obfuscator_slug'])); ?></code>
                </div>
            </div>
        </div>

        <div class="warning-box warning-warning">
            <span class="dashicons dashicons-warning"></span>
            <div class="warning-content">
                <strong><?php esc_html_e('¡ATENCIÓN! Por favor lee esto con cuidado', 'apta-shield'); ?></strong>
                <ul>
                    <li><?php esc_html_e('Guarda y añade a favoritos tu nueva URL de inicio de sesión antes de cerrar esta página.', 'apta-shield'); ?></li>
                    <li><?php esc_html_e('Si olvidas el slug secreto, no podrás ingresar al administrador de forma normal. Para solucionarlo, deberás desactivar el plugin renombrando su directorio vía FTP o base de datos.', 'apta-shield'); ?></li>
                    <li><?php esc_html_e('Si usas plugins de caché externa, te recomendamos vaciar la caché después de guardar estos cambios.', 'apta-shield'); ?></li>
                </ul>
            </div>
        </div>
    </div>
</div>
