document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const btnScan = document.getElementById('btnScan');
    const loadingState = document.getElementById('loadingState');
    const loadingMsg = document.getElementById('loadingMsg');
    const progressBar = document.getElementById('progressBar');
    const errorState = document.getElementById('errorState');
    const errorMsg = document.getElementById('errorMsg');
    const resultsState = document.getElementById('resultsState');
    
    // Results DOM elements
    const resTarget = document.getElementById('resTarget');
    const resTimestamp = document.getElementById('resTimestamp');
    const sslContent = document.getElementById('sslContent');
    const headersContent = document.getElementById('headersContent');
    const aiReportContent = document.getElementById('aiReportContent');
    const btnOpenReport = document.getElementById('btnOpenReport');

    let progressInterval = null;

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const target = document.getElementById('target').value.trim();
        const port = document.getElementById('port').value.trim() || '443';

        if (!target) return;

        // Reset view states
        resultsState.classList.add('hidden');
        errorState.classList.add('hidden');
        loadingState.classList.remove('hidden');
        btnScan.disabled = true;

        // Simulate progress bar movement and update messages
        let progress = 5;
        progressBar.style.width = `${progress}%`;
        loadingMsg.textContent = 'Limpando domínio e resolvendo hostname...';

        const stages = [
            { threshold: 25, msg: 'Iniciando handshakes de conexão SSL/TLS...' },
            { threshold: 50, msg: 'Analisando cabeçalhos HTTP e políticas de segurança...' },
            { threshold: 75, msg: 'Avaliando vazamento de informações do servidor...' },
            { threshold: 95, msg: 'Iniciando análise de vulnerabilidades orientada por IA no Vertex AI...' }
        ];

        progressInterval = setInterval(() => {
            if (progress < 95) {
                progress += Math.floor(Math.random() * 4) + 1;
                progressBar.style.width = `${progress}%`;
                
                const currentStage = stages.find(s => progress <= s.threshold);
                if (currentStage) {
                    loadingMsg.textContent = currentStage.msg;
                }
            }
        }, 300);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target, port })
            });

            const data = await response.json();

            clearInterval(progressInterval);
            progressBar.style.width = '100%';

            if (response.ok && data.success) {
                setTimeout(() => {
                    loadingState.classList.add('hidden');
                    renderResults(data, target, port);
                    btnScan.disabled = false;
                }, 500);
            } else {
                throw new Error(data.error || 'Ocorreu um erro desconhecido durante o escaneamento.');
            }

        } catch (err) {
            clearInterval(progressInterval);
            loadingState.classList.add('hidden');
            errorState.classList.remove('hidden');
            errorMsg.textContent = err.message;
            btnScan.disabled = false;
        }
    });

    function renderResults(data, target, port) {
        resTarget.textContent = `${data.ssl_results.hostname}:${port}`;
        resTimestamp.textContent = new Date().toLocaleString('pt-BR');

        renderSSL(data.ssl_results);
        renderHeaders(data.header_results);

        if (data.report_filename) {
            btnOpenReport.href = `/report/${data.report_filename}`;
            btnOpenReport.classList.remove('hidden');
        } else {
            btnOpenReport.classList.add('hidden');
        }

        if (data.ai_report) {
            aiReportContent.innerHTML = marked.parse(data.ai_report);
        } else {
            aiReportContent.innerHTML = '<p class="info-value">Nenhum relatório foi retornado pelo agente de IA.</p>';
        }

        resultsState.classList.remove('hidden');
    }

    function renderSSL(ssl) {
        const cert = ssl.certificate || {};
        const tls = ssl.tls_support || {};

        let certHtml = '';
        if (cert.success) {
            const expiryDate = new Date(cert.not_after).toLocaleDateString('pt-BR');
            const dayColorClass = cert.days_remaining > 30 ? 'badge-success' : (cert.days_remaining > 0 ? 'badge-warning' : 'badge-danger');
            const statusText = cert.is_expired ? 'Expirado' : 'Válido';

            certHtml = `
                <table class="info-table">
                    <tr>
                        <td class="info-label">Status do Certificado</td>
                        <td class="info-value"><span class="badge ${dayColorClass}">${statusText}</span></td>
                    </tr>
                    <tr>
                        <td class="info-label">Validade</td>
                        <td class="info-value">${cert.days_remaining} dias restantes (Expira em: ${expiryDate})</td>
                    </tr>
                    <tr>
                        <td class="info-label">Algoritmo de Assinatura</td>
                        <td class="info-value">${cert.signature_algorithm || 'Desconhecido'}</td>
                    </tr>
                    <tr>
                        <td class="info-label">Emissor</td>
                        <td class="info-value">${cert.issuer || 'N/A'}</td>
                    </tr>
                    <tr>
                        <td class="info-label">Subject (CN)</td>
                        <td class="info-value">${cert.subject || 'N/A'}</td>
                    </tr>
                </table>
            `;
        } else {
            certHtml = `
                <div class="header-status-item" style="border-left: 3px solid #ef4444; margin-bottom: 1rem;">
                    <span class="info-label" style="color: #ef4444;">Erro de Certificado</span>
                    <span class="badge badge-danger">Inválido / Inacessível</span>
                </div>
                <p style="font-size: 0.85rem; color: #fca5a5; font-family: monospace;">${cert.error || 'Não foi possível coletar dados do certificado.'}</p>
            `;
        }

        // Render TLS Versions Support list
        let tlsHtml = '<div class="tls-list">';
        for (const [version, status] of Object.entries(tls)) {
            let badgeClass = 'badge-danger';
            let label = 'Desabilitado';

            if (typeof status === 'object' && status.supported) {
                label = 'Habilitado';
                badgeClass = 'badge-success';
                // Highlight obsolete/insecure versions (TLSv1.0 & TLSv1.1)
                if (['TLSv1.0', 'TLSv1.1'].includes(version)) {
                    badgeClass = 'badge-warning';
                    label = 'Habilitado (Inseguro)';
                }
            } else if (typeof status === 'string') {
                label = 'Não suportado / Erro';
                badgeClass = 'badge-warning';
            }

            tlsHtml += `
                <div class="tls-item">
                    <span class="tls-name">${version}</span>
                    <span class="badge ${badgeClass}">${label}</span>
                </div>
            `;
        }
        tlsHtml += '</div>';

        sslContent.innerHTML = certHtml + tlsHtml;
    }

    function renderHeaders(headersData) {
        const scan = headersData.headers_scan || {};
        let html = '<div class="headers-check-list">';

        for (const [scheme, info] of Object.entries(scan)) {
            const isHttps = scheme === 'https';
            html += `
                <div class="headers-check-group">
                    <h4>Protocolo: ${scheme.toUpperCase()}</h4>
            `;

            if (info.error) {
                html += `
                    <div class="header-status-item" style="border-left: 3px solid #ef4444;">
                        <span class="header-name">Acesso</span>
                        <span class="badge badge-danger">Falhou</span>
                    </div>
                    <p style="font-size: 0.8rem; color: #fca5a5; font-family: monospace; margin-top: 0.25rem; padding: 0 0.5rem;">${info.error.slice(0, 80)}...</p>
                `;
            } else {
                const statusLabel = `HTTP ${info.status_code}`;
                html += `
                    <div class="header-status-item" style="margin-bottom: 0.5rem;">
                        <span class="header-name">Status do Servidor</span>
                        <span class="badge badge-success">${statusLabel}</span>
                    </div>
                `;

                // Missing vs Found security headers
                const missing = info.missing_security_headers || [];
                const found = info.headers_found || {};

                // Show found headers
                for (const [header, val] of Object.entries(found)) {
                    html += `
                        <div class="header-status-item" style="border-left: 3px solid #10b981;">
                            <span class="header-name">${header}</span>
                            <span class="badge badge-success">Presente</span>
                        </div>
                    `;
                }

                // Show missing security headers
                for (const header of missing) {
                    html += `
                        <div class="header-status-item" style="border-left: 3px solid #ef4444;">
                            <span class="header-name">${header}</span>
                            <span class="badge badge-danger">Ausente</span>
                        </div>
                    `;
                }

                // Server Banner Disclosures
                const disclosures = info.server_disclosure || {};
                if (Object.keys(disclosures).length > 0) {
                    html += `
                        <div class="server-banner-card">
                            <h4>Vazamento de Banner (Disclosures)</h4>
                            <ul class="server-banner-list">
                    `;
                    for (const [k, v] of Object.entries(disclosures)) {
                        html += `<li><strong>${k}:</strong> ${v}</li>`;
                    }
                    html += `
                            </ul>
                        </div>
                    `;
                }
            }

            html += `</div>`; // Close group
        }

        html += '</div>'; // Close list
        headersContent.innerHTML = html;
    }
});
