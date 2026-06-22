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
    initWizard();

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
                $('#url-obfuscator-warning-box').removeClass('hidden');
            } else {
                $('#url-obfuscator-subfields').addClass('disabled-section');
                $('#url-obfuscator-warning-box').addClass('hidden');
            }
        }
        if ($(this).attr('name') === 'captcha_enabled') {
            if ($(this).is(':checked')) {
                $('#captcha-subfields').removeClass('disabled-section');
            } else {
                $('#captcha-subfields').addClass('disabled-section');
            }
        }
        if ($(this).attr('name') === 'two_factor_enabled') {
            if ($(this).is(':checked')) {
                $('#two-factor-subfields').removeClass('disabled-section');
            } else {
                $('#two-factor-subfields').addClass('disabled-section');
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
                        data.threats.forEach(function(threat, index) {
                            const badgeClass = threat.type === 'malware' ? 'danger' : 'warning';
                            let actionHtml = '';
                            if (threat.type === 'core_modified') {
                                actionHtml = '<span class="text-muted">Usa reinstalación</span>';
                            } else {
                                if (data.is_pro) {
                                    actionHtml = `<button type="button" class="apta-btn apta-btn-danger apta-btn-sm apta-clean-threat-btn" data-index="${index}">Limpiar</button>`;
                                } else {
                                    actionHtml = '<span class="badge badge-warning">Pro Only</span>';
                                }
                            }
                            tableHtml += `<tr id="apta-threat-row-${index}">
                                <td><code>${escapeHtml(threat.file)}</code></td>
                                <td><span class="badge badge-${badgeClass}">${escapeHtml(threat.type_label)}</span></td>
                                <td>${escapeHtml(threat.desc)}</td>
                                <td>${actionHtml}</td>
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

    // Custom confirmation modal helper with dynamic styling support
    function customConfirm(title, message, onConfirm, type = 'danger') {
        const $modal = $('#apta-confirm-modal');
        const $title = $('#apta-modal-title');
        const $message = $('#apta-modal-message');
        const $icon = $modal.find('.modal-icon');
        const $confirmBtn = $('#apta-modal-confirm');
        
        $title.text(title);
        $message.text(message);
        
        // Reset classes
        $icon.removeClass('dashicons-shield dashicons-warning dashicons-info dashicons-update-alt text-danger text-warning text-primary text-success');
        $confirmBtn.removeClass('apta-btn-danger apta-btn-warning apta-btn-primary apta-btn-success');
        
        // Set type classes
        if (type === 'danger') {
            $icon.addClass('dashicons-shield text-danger');
            $confirmBtn.addClass('apta-btn-danger');
        } else if (type === 'warning') {
            $icon.addClass('dashicons-warning text-warning');
            $confirmBtn.addClass('apta-btn-warning');
        } else if (type === 'success') {
            $icon.addClass('dashicons-shield text-success');
            $confirmBtn.addClass('apta-btn-success');
        } else {
            $icon.addClass('dashicons-info text-primary');
            $confirmBtn.addClass('apta-btn-primary');
        }
        
        $modal.removeClass('hidden');
        
        // Remove previous event listeners
        $confirmBtn.off('click');
        $('#apta-modal-cancel').off('click');
        
        $confirmBtn.on('click', function() {
            $modal.addClass('hidden');
            onConfirm();
        });
        
        $('#apta-modal-cancel').on('click', function() {
            $modal.addClass('hidden');
        });
    }

    // 7.1 Clean threat action via AJAX
    $(document).on('click', '.apta-clean-threat-btn', function() {
        const $btn = $(this);
        const index = $btn.data('index');
        
        customConfirm(
            'Confirmar Desinfección',
            '¿Estás seguro de que deseas limpiar esta amenaza? Esta acción intentará eliminar el archivo malicioso o limpiar las inyecciones de código de tu base de datos.',
            function() {
                $btn.prop('disabled', true).html('<span class="apta-spinner"></span>');
                
                $.post(aptaShield.ajax_url, {
                    action: 'apta_shield_clean_threat',
                    threat_index: index,
                    nonce: aptaShield.nonce
                }, function(response) {
                    if (response.success) {
                        showToast(response.data, 'success');
                        $(`#apta-threat-row-${index}`).fadeOut(400, function() {
                            $(this).remove();
                            if ($('#apta-scan-tbody tr').length === 0) {
                                $('#apta-scan-details-list').addClass('hidden');
                                $('#apta-res-malware-count').text('0');
                                $('#apta-res-core-count').text('0');
                            }
                        });
                    } else {
                        showToast(response.data || 'Error al limpiar la amenaza.', 'error');
                        $btn.prop('disabled', false).text('Limpiar');
                    }
                }).fail(function() {
                    showToast('Error de red al intentar limpiar la amenaza.', 'error');
                    $btn.prop('disabled', false).text('Limpiar');
                });
            }
        );
    });

    // 8. One-Click Core Reinstallation
    $('#apta-run-reinstall').on('click', function() {
        customConfirm(
            'Reinstalar WordPress Core',
            aptaShield.messages.confirm_reinstall || '¿Estás seguro de que deseas reinstalar el núcleo oficial de WordPress? Esto sobrescribirá los archivos del núcleo modificados.',
            function() {
                const $btn = $('#apta-run-reinstall');
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
            },
            'danger'
        );
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
            customConfirm(
                'Vaciar Historial',
                aptaShield.messages.confirm_clear_audit || '¿Estás seguro de que deseas vaciar el historial de actividad de seguridad?',
                function() {
                    const $btn = $('#apta-clear-audit-btn');
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
                },
                'warning'
            );
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

    // 10. Onboarding Wizard Logic
    function initWizard() {
        // Reset Wizard click handler (always registered for settings page)
        $('#apta-reset-wizard-btn').on('click', function() {
            customConfirm(
                'Reiniciar Asistente',
                aptaShield.messages.confirm_reset_wizard || '¿Estás seguro de que deseas volver a ejecutar el asistente de configuración?',
                function() {
                    const $btn = $('#apta-reset-wizard-btn');
                    $btn.prop('disabled', true).html('<span class="apta-spinner"></span> Reiniciando...');

                    $.post(aptaShield.ajax_url, {
                        action: 'apta_shield_reset_wizard',
                        nonce: aptaShield.nonce
                    }, function(response) {
                        if (response.success) {
                            showToast(response.data, 'success');
                            window.location.reload();
                        } else {
                            showToast(response.data || aptaShield.messages.error, 'error');
                            $btn.prop('disabled', false).html('<span class="dashicons dashicons-update icon-btn"></span> Volver a ejecutar el Asistente');
                        }
                    }).fail(function() {
                        showToast(aptaShield.messages.error, 'error');
                        $btn.prop('disabled', false).html('<span class="dashicons dashicons-update icon-btn"></span> Volver a ejecutar el Asistente');
                    });
                },
                'warning'
            );
        });

        if (aptaShield.wizard_completed === 1) return;

        let currentWizardStep = 1;

        // Toggle obfuscator subfield
        $('#wizard_url_obfuscator_enabled').on('change', function() {
            if ($(this).is(':checked')) {
                $('#wizard-obfuscator-sub').removeClass('hidden');
            } else {
                $('#wizard-obfuscator-sub').addClass('hidden');
            }
        });

        // Toggle notifier subfield
        $('#wizard_notifier_enabled').on('change', function() {
            if ($(this).is(':checked')) {
                $('#wizard-notifier-sub').removeClass('hidden');
            } else {
                $('#wizard-notifier-sub').addClass('hidden');
            }
        });

        // Live slug cleaning
        $('#wizard_url_slug').on('input', function() {
            let val = $(this).val().toLowerCase().replace(/[^a-z0-9\-]/g, '');
            $(this).val(val);
        });

        // Next button click
        $('.btn-wizard-next').on('click', function() {
            if (currentWizardStep === 2) {
                // Validate custom login slug if enabled
                if ($('#wizard_url_obfuscator_enabled').is(':checked') && !$('#wizard_url_slug').val().trim()) {
                    showToast('Por favor, introduce un slug de acceso válido.', 'error');
                    return;
                }
            }

            goToStep(currentWizardStep + 1);
        });

        // Prev button click
        $('.btn-wizard-prev').on('click', function() {
            goToStep(currentWizardStep - 1);
        });

        function goToStep(step) {
            // Hide current pane
            $(`#wizard-step-${currentWizardStep}`).removeClass('active');
            
            // Update step indicator status
            if (step > currentWizardStep) {
                // Moving forward
                $(`.step-indicator[data-step="${currentWizardStep}"]`).removeClass('active').addClass('completed');
            } else {
                // Moving backward
                $(`.step-indicator[data-step="${currentWizardStep}"]`).removeClass('active');
                $(`.step-indicator[data-step="${step}"]`).removeClass('completed');
            }

            currentWizardStep = step;

            // Show new pane
            $(`#wizard-step-${currentWizardStep}`).addClass('active');
            $(`.step-indicator[data-step="${currentWizardStep}"]`).addClass('active');
        }

        // Complete Wizard button
        $('#apta-wizard-complete-btn').on('click', function() {
            const $btn = $(this);
            const originalHtml = $btn.html();

            // Validate notifier email
            if ($('#wizard_notifier_enabled').is(':checked')) {
                const emailVal = $('#wizard_notifier_email').val().trim();
                if (!emailVal || !emailVal.includes('@')) {
                    showToast('Por favor, introduce una dirección de correo válida.', 'error');
                    return;
                }
            }

            $btn.prop('disabled', true).html('<span class="apta-spinner"></span> Guardando...');

            // Serialize only wizard options to prevent duplicate form fields from overwriting values
            const formData = $('#apta-wizard-container :input').serialize() + '&action=apta_shield_complete_wizard&nonce=' + aptaShield.nonce;

            $.post(aptaShield.ajax_url, formData, function(response) {
                if (response.success) {
                    // Update step indicators
                    $(`.step-indicator[data-step="3"]`).removeClass('active').addClass('completed');
                    
                    // Show success step
                    $(`#wizard-step-${currentWizardStep}`).removeClass('active');
                    currentWizardStep = 'success';
                    $(`#wizard-step-success`).addClass('active');
                    showToast(response.data, 'success');
                } else {
                    showToast(response.data || aptaShield.messages.error, 'error');
                    $btn.prop('disabled', false).html(originalHtml);
                }
            }).fail(function() {
                showToast(aptaShield.messages.error, 'error');
                $btn.prop('disabled', false).html(originalHtml);
            });
        });

        // Enter dashboard button
        $('#apta-wizard-enter-dashboard').on('click', function() {
            window.location.reload();
        });
    }
});
