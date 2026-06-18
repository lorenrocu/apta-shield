jQuery(document).ready(function($) {
    // State management
    let initialFormState = '';
    let isScanning = false;
    
    // Audit log state
    let currentAuditPage = 1;
    let currentAuditSearch = '';
    let auditSearchTimeout = null;

    // Initialize Page
    initTabs();
    initBans();
    initAuditLogs();
    captureInitialFormState();
    initUrlPreview();

    // 1. Tabs Navigation
    function initTabs() {
        $('.apta-nav-item').on('click', function(e) {
            e.preventDefault();
            const targetTab = $(this).data('tab');
            
            // Update Active class in menu
            $('.apta-nav-item').removeClass('active');
            $(this).addClass('active');

            // Switch tab section
            $('.apta-tab-content').removeClass('active');
            $('#tab-' + targetTab).addClass('active');

            // Update URL hash
            window.location.hash = targetTab;

            // Load audit logs automatically when switching to audit tab
            if (targetTab === 'audit') {
                currentAuditPage = 1;
                loadAuditLogs();
            }
        });

        // Load tab based on URL hash if present
        const hash = window.location.hash.substring(1);
        if (hash && $('#tab-' + hash).length) {
            $(`.apta-nav-item[data-tab="${hash}"]`).click();
        }
    }

    // 2. Settings Dirty Checking
    function captureInitialFormState() {
        initialFormState = $('#apta-settings-form').serialize();
        hideSaveBar();
    }

    $('#apta-settings-form').on('change input', '.settings-trigger', function() {
        // Handle visual state for disabled sections
        if ($(this).attr('name') === 'brute_force_enabled') {
            if ($(this).is(':checked')) {
                $('#brute-force-subfields').removeClass('disabled-section');
            } else {
                $('#brute-force-subfields').addClass('disabled-section');
            }
        }
        if ($(this).attr('name') === 'url_obfuscator_enabled') {
            if ($(this).is(':checked')) {
                $('#url-obfuscator-subfields').removeClass('disabled-section');
            } else {
                $('#url-obfuscator-subfields').addClass('disabled-section');
            }
        }
        if ($(this).attr('name') === 'notifier_enabled') {
            if ($(this).is(':checked')) {
                $('#notifier-subfields').removeClass('disabled-section');
            } else {
                $('#notifier-subfields').addClass('disabled-section');
            }
        }

        const currentState = $('#apta-settings-form').serialize();
        if (currentState !== initialFormState) {
            showSaveBar();
        } else {
            hideSaveBar();
        }
    });

    function showSaveBar() {
        $('.apta-save-bar').addClass('show');
    }

    function hideSaveBar() {
        $('.apta-save-bar').removeClass('show');
    }

    // 3. Save Settings via AJAX
    $('#apta-settings-form').on('submit', function(e) {
        e.preventDefault();
        
        const $btn = $('#apta-save-btn');
        const originalText = $btn.text();
        
        $btn.prop('disabled', true).text(aptaShield.messages.saving);

        const formData = $(this).serialize() + '&action=apta_shield_save_settings&nonce=' + aptaShield.nonce;

        $.post(aptaShield.ajax_url, formData, function(response) {
            if (response.success) {
                showToast(response.data || aptaShield.messages.saved, 'success');
                captureInitialFormState();
            } else {
                showToast(response.data || aptaShield.messages.error, 'error');
            }
        }).fail(function() {
            showToast(aptaShield.messages.error, 'error');
        }).always(function() {
            $btn.prop('disabled', false).text(originalText);
        });
    });

    // 4. URL Preview Live Change
    function initUrlPreview() {
        const $input = $('#url_obfuscator_slug');
        const $preview = $('#apta-preview-link');
        if (!$input.length) return;
        const siteUrl = $preview.text().replace($input.val(), '');

        $input.on('input', function() {
            // Clean slug (alphanumeric and dashes only)
            let val = $(this).val().toLowerCase().replace(/[^a-z0-9\-]/g, '');
            $(this).val(val);
            $preview.text(siteUrl + val);
        });
    }

    // 5. Toast Notification System
    function showToast(message, type = 'success') {
        const $toast = $('#apta-toast');
        $toast.text(message)
            .removeClass('hidden apta-toast-success apta-toast-error')
            .addClass('apta-toast-' + type);

        setTimeout(function() {
            $toast.addClass('hidden');
        }, 5000);
    }

    // 6. IP Bans Management
    function initBans() {
        if (!$('#apta-bans-tbody').length) return;
        loadBansList();

        $('#apta-refresh-bans').on('click', function() {
            loadBansList();
        });

        // Unban action
        $('#apta-bans-tbody').on('click', '.apta-unban-btn', function() {
            const $btn = $(this);
            const banId = $btn.data('id');
            const ip = $btn.data('ip');
            
            $btn.prop('disabled', true).html('<span class="apta-spinner"></span>');

            $.post(aptaShield.ajax_url, {
                action: 'apta_shield_unban_ip',
                ban_id: banId,
                nonce: aptaShield.nonce
            }, function(response) {
                if (response.success) {
                    showToast(response.data, 'success');
                    loadBansList();
                } else {
                    showToast(response.data || aptaShield.messages.error, 'error');
                    $btn.prop('disabled', false).text('Desbloquear');
                }
            }).fail(function() {
                showToast(aptaShield.messages.error, 'error');
                $btn.prop('disabled', false).text('Desbloquear');
            });
        });
    }

    function loadBansList() {
        const $tbody = $('#apta-bans-tbody');
        if (!$tbody.length) return;
        $tbody.html('<tr class="apta-loading-row"><td colspan="5" style="text-align: center;"><span class="apta-spinner"></span> Cargando registros...</td></tr>');

        $.post(aptaShield.ajax_url, {
            action: 'apta_shield_get_bans',
            nonce: aptaShield.nonce
        }, function(response) {
            if (response.success) {
                const bans = response.data;
                if (bans.length === 0) {
                    $tbody.html('<tr><td colspan="5" style="text-align: center; color: var(--apta-text-muted);">No hay direcciones IP bloqueadas actualmente.</td></tr>');
                    return;
                }

                let html = '';
                bans.forEach(function(ban) {
                    html += `<tr>
                        <td><strong>${escapeHtml(ban.ip_address)}</strong></td>
                        <td><span class="badge badge-warning">${escapeHtml(ban.reason || 'Desconocida')}</span></td>
                        <td>${escapeHtml(ban.created_at)}</td>
                        <td><span class="text-danger">${escapeHtml(ban.banned_until)}</span></td>
                        <td>
                            <button type="button" class="apta-btn apta-btn-secondary apta-btn-sm apta-unban-btn" data-id="${ban.id}" data-ip="${ban.ip_address}">
                                Desbloquear
                            </button>
                        </td>
                    </tr>`;
                });
                $tbody.html(html);
            } else {
                $tbody.html('<tr><td colspan="5" style="text-align: center; color: var(--apta-danger);">Error al cargar IPs bloqueadas.</td></tr>');
            }
        }).fail(function() {
            $tbody.html('<tr><td colspan="5" style="text-align: center; color: var(--apta-danger);">Error al conectar con el servidor.</td></tr>');
        });
    }

    // Helper to escape HTML tags
    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    // 7. Malware & Integrity Scanner
    $('#apta-start-scan').on('click', function() {
        if (isScanning) return;
        
        isScanning = true;
        const $btn = $(this);
        $btn.prop('disabled', true).html('<span class="apta-spinner"></span> Analizando...');
        
        // Show console and reset states
        const $console = $('#apta-scan-console');
        const $logs = $('#apta-scan-logs');
        const $progress = $('#apta-scan-progress');
        const $percent = $('#apta-scan-percent');
        
        $console.removeClass('hidden');
        $logs.html('<p class="log-info">[+] Iniciando análisis del sitio...</p>');
        $progress.css('width', '0%');
        $percent.text('0%');

        $('#apta-scan-results-summary').addClass('hidden');
        $('#apta-scan-details-list').addClass('hidden');

        // Start batch scanning process
        runScanBatch('start', 0);
    });

    function runScanBatch(step, progress) {
        const $logs = $('#apta-scan-logs');
        const $progress = $('#apta-scan-progress');
        const $percent = $('#apta-scan-percent');

        $.post(aptaShield.ajax_url, {
            action: 'apta_shield_run_scan',
            step: step,
            progress: progress,
            nonce: aptaShield.nonce
        }, function(response) {
            if (response.success) {
                const data = response.data;
                
                // Append logs
                if (data.logs && data.logs.length) {
                    data.logs.forEach(function(log) {
                        let logClass = 'log-info';
                        if (log.indexOf('[x]') === 0 || log.indexOf('Error') >= 0 || log.indexOf('Encontrado') >= 0) {
                            logClass = 'log-danger';
                        } else if (log.indexOf('[+]') === 0 || log.indexOf('Completado') >= 0) {
                            logClass = 'log-success';
                        } else if (log.indexOf('[!]') === 0) {
                            logClass = 'log-warn';
                        }
                        $logs.append(`<p class="${logClass}">${escapeHtml(log)}</p>`);
                    });
                    $logs.scrollTop($logs[0].scrollHeight);
                }

                // Update progress bar
                const currentPercent = parseInt(data.percent || 0);
                $progress.css('width', currentPercent + '%');
                $percent.text(currentPercent + '%');

                if (data.status === 'running') {
                    // Trigger next chunk
                    runScanBatch(data.next_step, data.progress);
                } else if (data.status === 'completed') {
                    isScanning = false;
                    $('#apta-start-scan').prop('disabled', false).html('<span class="dashicons dashicons-search icon-btn"></span> Iniciar Escaneo de Archivos');
                    
                    // Show final report summary
                    $('#apta-res-core-count').text(data.core_modified_count || 0);
                    $('#apta-res-malware-count').text(data.malware_count || 0);
                    
                    const totalThreats = parseInt(data.core_modified_count || 0) + parseInt(data.malware_count || 0);
                    const $summary = $('#apta-scan-results-summary');
                    const $details = $('#apta-scan-details-list');
                    const $tbody = $('#apta-scan-tbody');

                    $summary.removeClass('hidden');

                    if (totalThreats > 0 && data.threats && data.threats.length) {
                        let tableHtml = '';
                        data.threats.forEach(function(threat) {
                            const badgeClass = threat.type === 'malware' ? 'danger' : 'warning';
                            tableHtml += `<tr>
                                <td><code>${escapeHtml(threat.file)}</code></td>
                                <td><span class="badge badge-${badgeClass}">${escapeHtml(threat.type_label)}</span></td>
                                <td>${escapeHtml(threat.desc)}</td>
                            </tr>`;
                        });
                        $tbody.html(tableHtml);
                        $details.removeClass('hidden');
                        showToast('El análisis ha completado. ¡Se detectaron amenazas!', 'error');
                    } else {
                        $tbody.html('');
                        $details.addClass('hidden');
                        showToast('El análisis ha completado de forma exitosa. Tu sitio está limpio.', 'success');
                    }
                }
            } else {
                isScanning = false;
                $('#apta-start-scan').prop('disabled', false).html('<span class="dashicons dashicons-search icon-btn"></span> Iniciar Escaneo de Archivos');
                $logs.append(`<p class="log-danger">[x] Error crítico en el escaneo: ${escapeHtml(response.data)}</p>`);
                showToast(response.data || 'Error al ejecutar el escaneo.', 'error');
            }
        }).fail(function() {
            isScanning = false;
            $('#apta-start-scan').prop('disabled', false).html('<span class="dashicons dashicons-search icon-btn"></span> Iniciar Escaneo de Archivos');
            $logs.append('<p class="log-danger">[x] Error de conexión de red al ejecutar el análisis.</p>');
            showToast('Error de conexión con el servidor.', 'error');
        });
    }

    // 8. One-Click Core Reinstallation
    $('#apta-run-reinstall').on('click', function() {
        if (!confirm(aptaShield.messages.confirm_reinstall)) {
            return;
        }

        const $btn = $(this);
        $btn.prop('disabled', true).html('<span class="apta-spinner"></span> Reinstalando...');

        const $progressBox = $('#apta-reinstall-progress-box');
        const $statusText = $('#apta-reinstall-status-text');

        $progressBox.removeClass('hidden');
        $statusText.text('Iniciando descarga y preparación del núcleo de WordPress...');

        $.post(aptaShield.ajax_url, {
            action: 'apta_shield_reinstall_core',
            nonce: aptaShield.nonce
        }, function(response) {
            if (response.success) {
                $statusText.text('Proceso completado. Los archivos del core fueron reemplazados.');
                showToast(response.data, 'success');
            } else {
                $statusText.text('Error en la reinstalación: ' + response.data);
                showToast(response.data || 'Ocurrió un error al reinstalar.', 'error');
            }
        }).fail(function() {
            $statusText.text('Error de conexión con el servidor.');
            showToast('Error de comunicación con el servidor durante la reinstalación.', 'error');
        }).always(function() {
            $btn.prop('disabled', false).html('<span class="dashicons dashicons-update-alt icon-btn"></span> Reinstalar WordPress Core en 1-Clic');
        });
    });

    // 9. Audit Logs Manager
    function initAuditLogs() {
        const $tbody = $('#apta-audit-tbody');
        if (!$tbody.length) return;

        // Search Input handler with Debounce
        $('#apta-audit-search').on('input', function() {
            clearTimeout(auditSearchTimeout);
            currentAuditSearch = $(this).val();
            
            auditSearchTimeout = setTimeout(function() {
                currentAuditPage = 1;
                loadAuditLogs();
            }, 400);
        });

        // Pagination buttons
        $('#apta-audit-prev-btn').on('click', function() {
            if (currentAuditPage > 1) {
                currentAuditPage--;
                loadAuditLogs();
            }
        });

        $('#apta-audit-next-btn').on('click', function() {
            currentAuditPage++;
            loadAuditLogs();
        });

        // Clear Audit Logs button
        $('#apta-clear-audit-btn').on('click', function() {
            if (!confirm(aptaShield.messages.confirm_clear_audit)) {
                return;
            }

            const $btn = $(this);
            $btn.prop('disabled', true).html('<span class="apta-spinner"></span> Vaciando...');

            $.post(aptaShield.ajax_url, {
                action: 'apta_shield_clear_audit_logs',
                nonce: aptaShield.nonce
            }, function(response) {
                if (response.success) {
                    showToast(response.data, 'success');
                    currentAuditPage = 1;
                    loadAuditLogs();
                } else {
                    showToast(response.data || aptaShield.messages.error, 'error');
                }
            }).fail(function() {
                showToast(aptaShield.messages.error, 'error');
            }).always(function() {
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-trash icon-btn"></span> Vaciar Historial');
            });
        });
    }

    function loadAuditLogs() {
        const $tbody = $('#apta-audit-tbody');
        if (!$tbody.length) return;

        $tbody.html('<tr class="apta-loading-row"><td colspan="5" style="text-align: center;"><span class="apta-spinner"></span> Cargando registros de actividad...</td></tr>');

        // Disable pagination buttons while loading
        $('#apta-audit-prev-btn, #apta-audit-next-btn').prop('disabled', true);

        $.post(aptaShield.ajax_url, {
            action: 'apta_shield_get_audit_logs',
            paged: currentAuditPage,
            search: currentAuditSearch,
            nonce: aptaShield.nonce
        }, function(response) {
            if (response.success) {
                const logs = response.data.logs;
                const totalPages = parseInt(response.data.total_pages || 1);
                const currentPage = parseInt(response.data.current_page || 1);
                const totalLogs = parseInt(response.data.total_logs || 0);

                if (logs.length === 0) {
                    $tbody.html('<tr><td colspan="5" style="text-align: center; color: var(--apta-text-muted);">No se encontraron registros de actividad.</td></tr>');
                    $('#apta-audit-pagination-info').text(`Página ${currentPage} de 1 (0 registros)`);
                    return;
                }

                let html = '';
                logs.forEach(function(log) {
                    // Determine badge class by action type
                    let badgeClass = 'secondary';
                    const act = log.action_type;
                    if (act.indexOf('success') >= 0 || act.indexOf('activated') >= 0 || act.indexOf('created') >= 0 || act.indexOf('registered') >= 0) {
                        badgeClass = 'success';
                    } else if (act.indexOf('failed') >= 0 || act.indexOf('deleted') >= 0 || act.indexOf('blocked') >= 0) {
                        badgeClass = 'danger';
                    } else if (act.indexOf('changed') >= 0 || act.indexOf('deactivated') >= 0 || act.indexOf('cleared') >= 0 || act.indexOf('trashed') >= 0) {
                        badgeClass = 'warning';
                    }

                    // Format role or user context
                    const usernameHtml = log.user_id > 0 ? `<strong>${escapeHtml(log.username)}</strong>` : `<span style="color:var(--apta-text-muted);">${escapeHtml(log.username)}</span>`;

                    html += `<tr>
                        <td><span style="color: #475569; font-size:12px;">${escapeHtml(log.formatted_date)}</span></td>
                        <td>${usernameHtml}</td>
                        <td><span class="badge badge-${badgeClass}">${escapeHtml(log.action_type)}</span></td>
                        <td><code>${escapeHtml(log.ip_address)}</code></td>
                        <td style="color: var(--apta-text-main); font-weight:500;">${escapeHtml(log.details)}</td>
                    </tr>`;
                });

                $tbody.html(html);

                // Update pagination info
                $('#apta-audit-pagination-info').text(`Página ${currentPage} de ${totalPages || 1} (${totalLogs} registros)`);

                // Update pagination buttons state
                $('#apta-audit-prev-btn').prop('disabled', currentPage <= 1);
                $('#apta-audit-next-btn').prop('disabled', currentPage >= totalPages);
            } else {
                $tbody.html('<tr><td colspan="5" style="text-align: center; color: var(--apta-danger);">Error al consultar la bitácora.</td></tr>');
            }
        }).fail(function() {
            $tbody.html('<tr><td colspan="5" style="text-align: center; color: var(--apta-danger);">Error al comunicar con el servidor.</td></tr>');
        });
    }
});
