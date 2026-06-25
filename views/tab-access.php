<?php
defined('ABSPATH') || exit;
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$is_pro_active = \AptaShield\Core\Plugin::is_pro_active();
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Seguridad de Acceso (Login Security)', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Detén los ataques automatizados en el punto de acceso y gestiona las políticas de inicio de sesión de tus usuarios.', 'apta-shield'); ?></p>
</div>

<!-- Grid for Brute Force and URL Obfuscator -->
<div class="apta-grid grid-2">
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

    <!-- URL Obfuscator Card -->
    <div class="apta-card">
        <div class="card-header">
            <h3><?php esc_html_e('Ocultar URL de Administración y Acceso', 'apta-shield'); ?></h3>
        </div>
        <div class="card-body">
            <div class="apta-form-group toggle-group">
                <div class="toggle-meta">
                    <label class="toggle-title"><?php esc_html_e('Activar Ofuscación de URL', 'apta-shield'); ?></label>
                    <span class="toggle-desc"><?php esc_html_e('Bloquea por completo wp-login.php y wp-admin. La URL secreta es la única forma de acceder.', 'apta-shield'); ?></span>
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
                    <span class="field-desc"><?php esc_html_e('Usa un slug fácil de recordar pero difícil de adivinar.', 'apta-shield'); ?></span>
                </div>

                <!-- Live URL Preview -->
                <div class="apta-live-url-preview">
                    <h4><?php esc_html_e('Tu URL de inicio de sesión actual:', 'apta-shield'); ?></h4>
                    <div class="url-preview-box">
                        <code id="apta-preview-link"><?php echo esc_url(home_url('/' . $settings['url_obfuscator_slug'])); ?></code>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Warning box for URL Obfuscator -->
<div class="warning-box warning-warning <?php echo !$settings['url_obfuscator_enabled'] ? 'hidden' : ''; ?>" id="url-obfuscator-warning-box">
    <span class="dashicons dashicons-warning"></span>
    <div class="warning-content">
        <strong><?php esc_html_e('¡ATENCIÓN! Por favor lee esto con cuidado', 'apta-shield'); ?></strong>
        <ul>
            <li><?php esc_html_e('Guarda y añade a favoritos tu nueva URL de inicio de sesión antes de cerrar esta página.', 'apta-shield'); ?></li>
            <li><?php esc_html_e('Si olvidas el slug secreto, no podrás ingresar al administrador de forma normal.', 'apta-shield'); ?></li>
        </ul>
    </div>
</div>

<!-- CAPTCHA Card -->
<div class="apta-card">
    <div class="card-header">
        <h3><?php esc_html_e('Protección CAPTCHA (Turnstile / hCaptcha)', 'apta-shield'); ?></h3>
    </div>
    <div class="card-body">
        <div class="apta-form-group toggle-group">
            <div class="toggle-meta">
                <label class="toggle-title"><?php esc_html_e('Activar Verificación CAPTCHA', 'apta-shield'); ?></label>
                <span class="toggle-desc"><?php esc_html_e('Agrega un control CAPTCHA en los accesos clave para detener a bots de spam y de fuerza bruta.', 'apta-shield'); ?></span>
            </div>
            <label class="apta-switch">
                <input type="checkbox" name="captcha_enabled" id="captcha_enabled" value="1" <?php checked(1, !empty($settings['captcha_enabled'])); ?> class="settings-trigger">
                <span class="slider round"></span>
            </label>
        </div>

        <div class="apta-settings-subfields <?php echo empty($settings['captcha_enabled']) ? 'disabled-section' : ''; ?>" id="captcha-subfields">
            <div class="apta-grid grid-2" style="margin-bottom: 0;">
                <div class="apta-form-group">
                    <label class="form-label"><?php esc_html_e('Proveedor de CAPTCHA', 'apta-shield'); ?></label>
                    <select name="captcha_provider" id="captcha_provider" class="apta-input settings-trigger">
                        <option value="turnstile" <?php selected('turnstile', $settings['captcha_provider']); ?>><?php esc_html_e('Cloudflare Turnstile (Recomendado)', 'apta-shield'); ?></option>
                        <option value="hcaptcha" <?php selected('hcaptcha', $settings['captcha_provider']); ?>><?php esc_html_e('hCaptcha', 'apta-shield'); ?></option>
                    </select>
                </div>

                <div class="apta-form-group">
                    <label for="captcha_site_key" class="form-label"><?php esc_html_e('Clave de Sitio (Site Key)', 'apta-shield'); ?></label>
                    <input type="text" id="captcha_site_key" name="captcha_site_key" class="apta-input settings-trigger" value="<?php echo esc_attr($settings['captcha_site_key']); ?>" placeholder="0x4AAAAAA...">
                </div>
            </div>

            <div class="apta-form-group">
                <label for="captcha_secret_key" class="form-label"><?php esc_html_e('Clave Secreta (Secret Key)', 'apta-shield'); ?></label>
                <input type="password" id="captcha_secret_key" name="captcha_secret_key" class="apta-input settings-trigger" value="<?php echo esc_attr($settings['captcha_secret_key']); ?>" placeholder="••••••••••••••••••••">
            </div>

            <!-- Forms mapping -->
            <div style="margin-top: 20px;">
                <h4 class="form-label" style="margin-bottom: 12px;"><?php esc_html_e('Habilitar CAPTCHA en:', 'apta-shield'); ?></h4>
                <div class="captcha-integrations-list" style="display: flex; flex-direction: column; gap: 10px;">
                    <!-- Free Forms -->
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                        <input type="checkbox" name="captcha_on_login" value="1" <?php checked(1, !empty($settings['captcha_on_login'])); ?> class="settings-trigger">
                        <?php esc_html_e('Formulario de Login Nativo', 'apta-shield'); ?>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                        <input type="checkbox" name="captcha_on_register" value="1" <?php checked(1, !empty($settings['captcha_on_register'])); ?> class="settings-trigger">
                        <?php esc_html_e('Formulario de Registro Nativo', 'apta-shield'); ?>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                        <input type="checkbox" name="captcha_on_lostpassword" value="1" <?php checked(1, !empty($settings['captcha_on_lostpassword'])); ?> class="settings-trigger">
                        <?php esc_html_e('Formulario de Recuperación de Contraseña', 'apta-shield'); ?>
                    </label>

                    <!-- Pro forms integrations -->
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; <?php echo !$is_pro_active ? 'color: var(--apta-text-muted);' : ''; ?>">
                        <input type="checkbox" name="captcha_on_comments" value="1" <?php echo !$is_pro_active ? 'disabled' : ''; ?> <?php checked(1, !empty($settings['captcha_on_comments'])); ?> class="settings-trigger">
                        <?php esc_html_e('Formulario de Comentarios', 'apta-shield'); ?>
                        <?php if (!$is_pro_active) : ?>
                            <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3; font-size: 9px; padding: 1px 4px;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
                        <?php endif; ?>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; <?php echo !$is_pro_active ? 'color: var(--apta-text-muted);' : ''; ?>">
                        <input type="checkbox" name="captcha_on_woocommerce" value="1" <?php echo !$is_pro_active ? 'disabled' : ''; ?> <?php checked(1, !empty($settings['captcha_on_woocommerce'])); ?> class="settings-trigger">
                        <?php esc_html_e('Formularios de WooCommerce (Login, Checkout)', 'apta-shield'); ?>
                        <?php if (!$is_pro_active) : ?>
                            <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3; font-size: 9px; padding: 1px 4px;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
                        <?php endif; ?>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; <?php echo !$is_pro_active ? 'color: var(--apta-text-muted);' : ''; ?>">
                        <input type="checkbox" name="captcha_on_elementor" value="1" <?php echo !$is_pro_active ? 'disabled' : ''; ?> <?php checked(1, !empty($settings['captcha_on_elementor'])); ?> class="settings-trigger">
                        <?php esc_html_e('Formularios de Elementor', 'apta-shield'); ?>
                        <?php if (!$is_pro_active) : ?>
                            <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3; font-size: 9px; padding: 1px 4px;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
                        <?php endif; ?>
                    </label>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Two-Factor Authentication (2FA) Card (Pro promo/integration placeholder) -->
<div class="apta-card pro-feature-card">
    <div class="card-header flex-header">
        <h3><?php esc_html_e('Autenticación de Doble Factor (2FA)', 'apta-shield'); ?></h3>
        <?php if (!$is_pro_active) : ?>
            <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3;"><?php esc_html_e('Función PRO', 'apta-shield'); ?></span>
        <?php endif; ?>
    </div>
    <div class="card-body" style="position: relative;">
        <p style="font-size: 13px; color: var(--apta-text-muted); line-height: 1.6; margin: 0 0 16px 0;">
            <?php esc_html_e('Asegura el acceso a las cuentas administrativas añadiendo un segundo factor de verificación (TOTP) compatible con aplicaciones como Google Authenticator, Microsoft Authenticator o Authy.', 'apta-shield'); ?>
        </p>
        
        <?php if (!$is_pro_active) : ?>
        <div style="background: rgba(248, 250, 252, 0.85); border: 1px dashed var(--apta-border); border-radius: var(--apta-radius-sm); padding: 20px; text-align: center;">
            <span class="dashicons dashicons-lock" style="font-size: 32px; width: 32px; height: 32px; color: var(--apta-danger); margin-bottom: 8px;"></span>
            <?php if (defined('APTA_SHIELD_PRO_VERSION')) : ?>
                <h4 style="font-size: 14px; font-weight: 700; margin: 0 0 4px 0;"><?php esc_html_e('Activa tu licencia Pro para activar el Doble Factor', 'apta-shield'); ?></h4>
                <p style="font-size: 12px; color: var(--apta-text-muted); margin: 0 0 12px 0;"><?php esc_html_e('Introduce y activa tu clave de licencia en la pestaña "Licencia PRO" para desbloquear esta característica.', 'apta-shield'); ?></p>
            <?php else : ?>
                <h4 style="font-size: 14px; font-weight: 700; margin: 0 0 4px 0;"><?php esc_html_e('Obtén Apta Shield Pro para activar el Doble Factor', 'apta-shield'); ?></h4>
                <p style="font-size: 12px; color: var(--apta-text-muted); margin: 0 0 12px 0;"><?php esc_html_e('Protege las cuentas de administradores y editores de manera definitiva contra el secuestro de credenciales.', 'apta-shield'); ?></p>
            <?php endif; ?>
        </div>
        <?php else : ?>
            <div class="apta-form-group toggle-group" style="margin-bottom: 16px;">
                <div class="toggle-meta">
                    <label class="toggle-title"><?php esc_html_e('Habilitar Autenticación de Doble Factor (2FA)', 'apta-shield'); ?></label>
                    <span class="toggle-desc"><?php esc_html_e('Activa globalmente la protección de doble factor (OTP) para cuentas con privilegios administrativos.', 'apta-shield'); ?></span>
                </div>
                <label class="apta-switch">
                    <input type="checkbox" name="two_factor_enabled" id="two_factor_enabled" value="1" <?php checked(1, !empty($settings['two_factor_enabled'])); ?> class="settings-trigger">
                    <span class="slider round"></span>
                </label>
            </div>
            <div class="apta-settings-subfields <?php echo empty($settings['two_factor_enabled']) ? 'disabled-section' : ''; ?>" id="two-factor-subfields">
                <?php do_action('apta_shield_pro_render_2fa_settings'); ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Active Sessions & Password Policies -->
<div class="apta-card">
    <div class="card-header flex-header">
        <h3><?php esc_html_e('Políticas de Contraseñas y Sesiones', 'apta-shield'); ?></h3>
    </div>
    <div class="card-body">
        <div class="apta-grid grid-2" style="margin-bottom: 0;">
            <!-- Password policies -->
            <div>
                <h4 class="form-label" style="margin-bottom: 8px;"><?php esc_html_e('Políticas de Contraseña', 'apta-shield'); ?></h4>
                <p style="font-size: 12px; color: var(--apta-text-muted); margin-bottom: 12px;"><?php esc_html_e('Forzar complejidad y fecha de expiración para todas las contraseñas de los usuarios.', 'apta-shield'); ?></p>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; <?php echo !$is_pro_active ? 'color: var(--apta-text-muted);' : ''; ?>">
                        <input type="checkbox" name="password_strong_force" value="1" <?php echo !$is_pro_active ? 'disabled' : ''; ?> <?php checked(1, !empty($settings['password_strong_force'])); ?> class="settings-trigger">
                        <?php esc_html_e('Forzar contraseñas fuertes', 'apta-shield'); ?>
                        <?php if (!$is_pro_active) : ?>
                            <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3; font-size: 9px; padding: 1px 4px;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
                        <?php endif; ?>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; <?php echo !$is_pro_active ? 'color: var(--apta-text-muted);' : ''; ?>">
                        <input type="checkbox" name="password_expiration" value="1" <?php echo !$is_pro_active ? 'disabled' : ''; ?> <?php checked(1, !empty($settings['password_expiration'])); ?> class="settings-trigger">
                        <?php esc_html_e('Expiración periódica (30 días)', 'apta-shield'); ?>
                        <?php if (!$is_pro_active) : ?>
                            <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3; font-size: 9px; padding: 1px 4px;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
                        <?php endif; ?>
                    </label>
                </div>
            </div>

            <!-- Sessions -->
            <div>
                <h4 class="form-label" style="margin-bottom: 8px;"><?php esc_html_e('Tus Sesiones Activas', 'apta-shield'); ?></h4>
                <p style="font-size: 12px; color: var(--apta-text-muted); margin-bottom: 12px;"><?php esc_html_e('Dispositivos y navegadores actualmente conectados con tu usuario.', 'apta-shield'); ?></p>
                
                <div class="active-sessions-list" style="border: 1px solid var(--apta-border); border-radius: var(--apta-radius-sm); padding: 12px; background-color: #f8fafc;">
                    <?php
                    $sessions = wp_get_all_sessions();
                    $current_token = wp_get_session_token();
                    if (!empty($sessions)) :
                        foreach ($sessions as $token => $session) :
                            $is_current = ($token === $current_token);
                            $ua = isset($session['ua']) ? $session['ua'] : '';
                            $ip = isset($session['ip']) ? $session['ip'] : '';
                            $login_time = isset($session['login']) ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $session['login']) : '';
                            ?>
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #e2e8f0; font-size: 12px; <?php echo $is_current ? 'font-weight: 600;' : ''; ?>">
                                <div>
                                    <span class="dashicons dashicons-desktop" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle; margin-right: 4px;"></span>
                                    <span><?php echo esc_html($ip); ?></span>
                                    <span style="font-size: 10px; color: var(--apta-text-muted);"><?php echo $is_current ? ' (' . esc_html__('Esta sesión', 'apta-shield') . ')' : ''; ?></span>
                                    <br>
                                    <span style="font-size: 10px; color: var(--apta-text-muted); margin-left: 18px;"><?php echo esc_html($login_time); ?></span>
                                </div>
                                <div>
                                    <?php if ($is_pro_active) : ?>
                                        <!-- Remote logout for Pro -->
                                        <?php if (!$is_current) : ?>
                                            <button type="button" class="apta-btn apta-btn-secondary apta-btn-sm btn-logout-session" data-token="<?php echo esc_attr($token); ?>" style="font-size: 10px; padding: 3px 6px;"><?php esc_html_e('Cerrar', 'apta-shield'); ?></button>
                                        <?php endif; ?>
                                    <?php else : ?>
                                        <span class="apta-version" style="background-color: #ffe4e6; color: #be123c; border-color: #fecdd3; font-size: 9px; padding: 1px 4px;"><?php esc_html_e('PRO', 'apta-shield'); ?></span>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <?php
                        endforeach;
                    else :
                        echo '<p style="font-size: 12px; color: var(--apta-text-muted); margin: 0;">' . esc_html__('No hay sesiones registradas.', 'apta-shield') . '</p>';
                    endif;
                    ?>
                </div>
            </div>
        </div>
    </div>
</div>
