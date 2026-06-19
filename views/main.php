<?php
defined('ABSPATH') || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

// Wizard status check
$wizard_completed = (int) get_option('apta_shield_wizard_completed', 0);

// Calculate basic security score (max 100)
$score = 0;
if ($settings['firewall_enabled']) $score += 15;
if ($settings['brute_force_enabled']) $score += 15;
if ($settings['url_obfuscator_enabled']) $score += 15;
if (!empty($settings['hardening_headers'])) $score += 10;
if (!empty($settings['hardening_file_edit'])) $score += 10;
if (!empty($settings['hardening_xmlrpc'])) $score += 10;
if (!empty($settings['hardening_author_scan'])) $score += 10;

// Check if a scan has run
$last_scan = get_option('apta_shield_last_scan_result', null);
if ($last_scan !== null && empty($last_scan['malware_count']) && empty($last_scan['core_modified_count'])) {
    $score += 15;
} elseif ($last_scan === null) {
    $score += 5; // Scan never run, partial score
}

// Get active bans count
global $wpdb;
$bans_table = \AptaShield\Common\Database::get_bans_table();
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
$active_bans = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM $bans_table WHERE banned_until > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    current_time('mysql')
));
$active_bans = intval($active_bans);

// Get total blocked events count
$logs_table = \AptaShield\Common\Database::get_logs_table();
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$total_blocked = $wpdb->get_var("SELECT COUNT(*) FROM $logs_table WHERE event_type IN ('firewall_block', 'login_fail')");
$total_blocked = intval($total_blocked);
?>

<div class="apta-dashboard-wrap">
    <!-- Header -->
    <header class="apta-header">
        <div class="apta-logo-area">
            <span class="dashicons dashicons-shield-alt apta-shield-icon"></span>
            <h1>Apta Shield <span class="apta-version">v<?php echo esc_html(APTA_SHIELD_VERSION); ?></span></h1>
        </div>
        <div class="apta-site-status">
            <span class="apta-status-dot <?php echo $score >= 75 ? 'status-good' : 'status-warn'; ?>"></span>
            <span class="apta-status-text">
                <?php echo $score >= 75 ? esc_html__('Tu sitio está seguro', 'apta-shield') : esc_html__('Requiere atención', 'apta-shield'); ?>
            </span>
        </div>
    </header>

    <!-- Main Container -->
    <div class="apta-container <?php echo !$wizard_completed ? 'apta-wizard-active' : ''; ?>">
        <!-- Sidebar Navigation -->
        <aside class="apta-sidebar">
            <nav class="apta-nav">
                <a href="#overview" class="apta-nav-item active" data-tab="overview">
                    <span class="dashicons dashicons-dashboard"></span>
                    <?php esc_html_e('Resumen', 'apta-shield'); ?>
                </a>
                <a href="#scanner" class="apta-nav-item <?php echo !$wizard_completed ? 'apta-nav-disabled' : ''; ?>" data-tab="scanner">
                    <span class="dashicons dashicons-search"></span>
                    <?php esc_html_e('Escáner de Virus', 'apta-shield'); ?>
                </a>
                <a href="#firewall" class="apta-nav-item <?php echo !$wizard_completed ? 'apta-nav-disabled' : ''; ?>" data-tab="firewall">
                    <span class="dashicons dashicons-html"></span>
                    <?php esc_html_e('Firewall y Fuerza Bruta', 'apta-shield'); ?>
                </a>
                <a href="#obfuscator" class="apta-nav-item <?php echo !$wizard_completed ? 'apta-nav-disabled' : ''; ?>" data-tab="obfuscator">
                    <span class="dashicons dashicons-admin-links"></span>
                    <?php esc_html_e('Ocultar URL', 'apta-shield'); ?>
                </a>
                <a href="#hardening" class="apta-nav-item <?php echo !$wizard_completed ? 'apta-nav-disabled' : ''; ?>" data-tab="hardening">
                    <span class="dashicons dashicons-admin-tools"></span>
                    <?php esc_html_e('Endurecimiento', 'apta-shield'); ?>
                </a>
                <a href="#audit" class="apta-nav-item <?php echo !$wizard_completed ? 'apta-nav-disabled' : ''; ?>" data-tab="audit">
                    <span class="dashicons dashicons-media-text"></span>
                    <?php esc_html_e('Registro de Actividad', 'apta-shield'); ?>
                </a>
                <a href="#settings" class="apta-nav-item <?php echo !$wizard_completed ? 'apta-nav-disabled' : ''; ?>" data-tab="settings">
                    <span class="dashicons dashicons-admin-generic"></span>
                    <?php esc_html_e('Ajustes y Alertas', 'apta-shield'); ?>
                </a>
            </nav>
        </aside>

        <!-- Main Content Area -->
        <main class="apta-content">
            <!-- Alert Toast Container -->
            <div id="apta-toast" class="apta-toast hidden"></div>

            <form id="apta-settings-form" method="post">
                <!-- Tab: Overview -->
                <section id="tab-overview" class="apta-tab-content active">
                    <?php include APTA_SHIELD_PATH . 'views/tab-overview.php'; ?>
                </section>

                <!-- Tab: Scanner -->
                <section id="tab-scanner" class="apta-tab-content">
                    <?php include APTA_SHIELD_PATH . 'views/tab-scanner.php'; ?>
                </section>

                <!-- Tab: Firewall -->
                <section id="tab-firewall" class="apta-tab-content">
                    <?php include APTA_SHIELD_PATH . 'views/tab-firewall.php'; ?>
                </section>

                <!-- Tab: Obfuscator -->
                <section id="tab-obfuscator" class="apta-tab-content">
                    <?php include APTA_SHIELD_PATH . 'views/tab-obfuscator.php'; ?>
                </section>

                <!-- Tab: Hardening -->
                <section id="tab-hardening" class="apta-tab-content">
                    <?php include APTA_SHIELD_PATH . 'views/tab-hardening.php'; ?>
                </section>

                <!-- Tab: Audit Log -->
                <section id="tab-audit" class="apta-tab-content">
                    <?php include APTA_SHIELD_PATH . 'views/tab-audit.php'; ?>
                </section>

                <!-- Tab: Settings -->
                <section id="tab-settings" class="apta-tab-content">
                    <?php include APTA_SHIELD_PATH . 'views/tab-settings.php'; ?>
                </section>

                <!-- Floating Save Bar (Visible when settings are dirty) -->
                <?php if ($wizard_completed) : ?>
                <div class="apta-save-bar">
                    <p><?php esc_html_e('Tienes cambios sin guardar en tu configuración.', 'apta-shield'); ?></p>
                    <button type="submit" class="apta-btn apta-btn-primary" id="apta-save-btn">
                        <?php esc_html_e('Guardar Cambios', 'apta-shield'); ?>
                    </button>
                </div>
                <?php endif; ?>
            </form>
        </main>
    </div>
</div>
