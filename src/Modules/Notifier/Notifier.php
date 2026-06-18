<?php

namespace AptaShield\Modules\Notifier;

defined('ABSPATH') || exit;

use AptaShield\Modules\ModuleInterface;
use AptaShield\Core\Plugin;

/**
 * Class Notifier
 * Sends email alert notifications to the administrator.
 */
class Notifier implements ModuleInterface {

    /**
     * Start the module.
     */
    public function run() {
        // Handled through direct method calls from other modules
    }

    /**
     * Send email alert for Brute Force IP ban.
     *
     * @param string $ip
     * @param int $duration_minutes
     */
    public function send_brute_force_alert($ip, $duration_minutes) {
        $settings = Plugin::get_instance()->get_settings();
        if (empty($settings['notifier_enabled']) || empty($settings['notifier_email'])) {
            return;
        }

        $to = $settings['notifier_email'];
        // translators: %s: Banned IP address.
        $subject = sprintf(__('[Apta Shield] Alerta: Dirección IP %s Bloqueada', 'apta-shield'), $ip);
        
        $body = $this->get_email_template(
            __('Dirección IP Bloqueada', 'apta-shield'),
            sprintf(
                // translators: 1: IP address, 2: Ban duration in minutes.
                __('La dirección IP <strong>%1$s</strong> ha sido bloqueada temporalmente por <strong>%2$d minutos</strong> debido a reiterados intentos de inicio de sesión fallidos en tu sitio web.', 'apta-shield'),
                $ip,
                $duration_minutes
            ),
            'warning'
        );

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        wp_mail($to, $subject, $body, $headers);
    }

    /**
     * Send email alert when threats are found during a scan.
     *
     * @param array $scan_results
     */
    public function send_scan_alert($scan_results) {
        $settings = Plugin::get_instance()->get_settings();
        if (empty($settings['notifier_enabled']) || empty($settings['notifier_email'])) {
            return;
        }

        $to = $settings['notifier_email'];
        $subject = __('[Apta Shield] ¡Amenazas de Seguridad Detectadas!', 'apta-shield');

        $threats_html = '<ul>';
        foreach (array_slice($scan_results['threats'], 0, 10) as $threat) {
            $threats_html .= sprintf(
                '<li><strong>%s</strong>: <code>%s</code> - %s</li>',
                esc_html($threat['type_label']),
                esc_html($threat['file']),
                esc_html($threat['desc'])
            );
        }
        if (count($scan_results['threats']) > 10) {
            $threats_html .= sprintf('<li>... y %d amenazas más.</li>', count($scan_results['threats']) - 10);
        }
        $threats_html .= '</ul>';

        $message = sprintf(
            // translators: %s: HTML list of detected security threats.
            __('El análisis de virus e integridad completado ha detectado las siguientes discrepancias en tu instalación:<br><br>%s<br><br>Por favor, ingresa al panel de control de seguridad para solucionar o reinstalar el núcleo.', 'apta-shield'),
            $threats_html
        );

        $body = $this->get_email_template(
            __('Amenazas de Seguridad Encontradas', 'apta-shield'),
            $message,
            'danger'
        );

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        wp_mail($to, $subject, $body, $headers);
    }

    /**
     * Send email alert when WordPress Core is reinstalled.
     */
    public function send_reinstall_alert() {
        $settings = Plugin::get_instance()->get_settings();
        if (empty($settings['notifier_enabled']) || empty($settings['notifier_email'])) {
            return;
        }

        $to = $settings['notifier_email'];
        $subject = __('[Apta Shield] Restauración: WordPress Core Reinstalado', 'apta-shield');
        
        $body = $this->get_email_template(
            __('Restauración del Core Completada', 'apta-shield'),
            __('Los archivos del núcleo de WordPress se han reinstalado de forma exitosa en tu servidor desde los servidores oficiales de wordpress.org para garantizar la integridad y eliminar cualquier archivo alterado.', 'apta-shield'),
            'success'
        );

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        wp_mail($to, $subject, $body, $headers);
    }

    /**
     * Helper to render dynamic HTML template for emails.
     *
     * @param string $title
     * @param string $message
     * @param string $type success|warning|danger
     * @return string HTML body
     */
    private function get_email_template($title, $message, $type = 'success') {
        $colors = [
            'success' => '#10b981',
            'warning' => '#f59e0b',
            'danger'  => '#ef4444'
        ];
        
        $color = isset($colors[$type]) ? $colors[$type] : '#3b82f6';
        $site_name = get_bloginfo('name');
        $site_url = home_url();

        return '
        <html>
        <body style="margin: 0; padding: 20px; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); border: 1px solid #e5e7eb;">
                <div style="background-color: ' . $color . '; padding: 30px; text-align: center; color: #ffffff;">
                    <h2 style="margin: 0; font-size: 22px; font-weight: 700;">' . esc_html($title) . '</h2>
                </div>
                <div style="padding: 30px; color: #374151; font-size: 15px; line-height: 1.6;">
                    <p style="margin-top: 0;">Hola,</p>
                    <p>' . $message . '</p>
                    <p style="margin-bottom: 0;">Atentamente,<br><strong>Apta Shield Engine</strong></p>
                </div>
                <div style="background-color: #f9fafb; padding: 20px; text-align: center; font-size: 12px; color: #9ca3af; border-top: 1px solid #e5e7eb;">
                    Este es un correo automático enviado por el plugin Apta Shield en <a href="' . esc_url($site_url) . '" style="color: #3b82f6; text-decoration: none;">' . esc_html($site_name) . '</a>.
                </div>
            </div>
        </body>
        </html>';
    }
}
