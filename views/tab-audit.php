<?php
defined('ABSPATH') || exit;
?>

<div class="apta-section-title">
    <h2><?php esc_html_e('Registro de Actividad (Audit Log)', 'apta-shield'); ?></h2>
    <p><?php esc_html_e('Registra y audita todas las acciones relevantes de los usuarios, cambios de configuración, inicios de sesión y modificaciones críticas.', 'apta-shield'); ?></p>
</div>

<div class="apta-card">
    <div class="card-header flex-header">
        <h3><?php esc_html_e('Bitácora del Sitio', 'apta-shield'); ?></h3>
        <div class="header-actions">
            <button type="button" class="apta-btn apta-btn-danger" id="apta-clear-audit-btn">
                <span class="dashicons dashicons-trash icon-btn"></span>
                <?php esc_html_e('Vaciar Historial', 'apta-shield'); ?>
            </button>
        </div>
    </div>
    
    <div class="card-body">
        <!-- Search and Filter Bar -->
        <div class="audit-filter-bar">
            <div class="apta-form-group">
                <input type="text" id="apta-audit-search" class="apta-input" placeholder="<?php esc_attr_e('Buscar por usuario, acción o IP...', 'apta-shield'); ?>" style="max-width: 100%; width: 320px;">
            </div>
        </div>

        <!-- Audit Table -->
        <div class="table-responsive" style="margin-top: 20px;">
            <table class="apta-table">
                <thead>
                    <tr>
                        <th style="width: 160px;"><?php esc_html_e('Fecha y Hora', 'apta-shield'); ?></th>
                        <th style="width: 120px;"><?php esc_html_e('Usuario', 'apta-shield'); ?></th>
                        <th style="width: 120px;"><?php esc_html_e('Acción', 'apta-shield'); ?></th>
                        <th style="width: 120px;"><?php esc_html_e('Dirección IP', 'apta-shield'); ?></th>
                        <th><?php esc_html_e('Detalles del Evento', 'apta-shield'); ?></th>
                    </tr>
                </thead>
                <tbody id="apta-audit-tbody">
                    <tr class="apta-loading-row">
                        <td colspan="5" style="text-align: center;">
                            <span class="apta-spinner"></span> <?php esc_html_e('Cargando registros...', 'apta-shield'); ?>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Pagination Controls -->
        <div class="audit-pagination-wrapper">
            <span class="pagination-info" id="apta-audit-pagination-info"><?php esc_html_e('Página 1 de 1 (0 registros)', 'apta-shield'); ?></span>
            <div class="pagination-buttons">
                <button type="button" class="apta-btn apta-btn-secondary" id="apta-audit-prev-btn" disabled>
                    <?php esc_html_e('Anterior', 'apta-shield'); ?>
                </button>
                <button type="button" class="apta-btn apta-btn-secondary" id="apta-audit-next-btn" disabled>
                    <?php esc_html_e('Siguiente', 'apta-shield'); ?>
                </button>
            </div>
        </div>
    </div>
</div>
