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
    const formsContent = document.getElementById('formsContent');
    const vulnsContent = document.getElementById('vulnsContent');
    const aiReportContent = document.getElementById('aiReportContent');
    const btnOpenReport = document.getElementById('btnOpenReport');

    let progressInterval = null;

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const target = document.getElementById('target').value.trim();

        if (!target) return;

        // Reset view states
        resultsState.classList.add('hidden');
        errorState.classList.add('hidden');
        loadingState.classList.remove('hidden');
        btnScan.disabled = true;

        // Simulate progress bar movement and update messages
        let progress = 5;
        progressBar.style.width = `${progress}%`;
        loadingMsg.textContent = 'Limpando endereço e resolvendo hostname...';

        const stages = [
            { threshold: 25, msg: 'Iniciando rastreamento de parâmetros GET e formulários HTML...' },
            { threshold: 50, msg: 'Coletando formulários e analisando tags de campos de input...' },
            { threshold: 75, msg: 'Injetando payloads SQL em parâmetros e monitorando assinaturas de erro...' },
            { threshold: 95, msg: 'Avaliando resposta da base de dados e gerando parecer com Gemini...' }
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
                body: JSON.stringify({ target })
            });

            const data = await response.json();

            clearInterval(progressInterval);
            progressBar.style.width = '100%';

            if (response.ok && data.success) {
                setTimeout(() => {
                    loadingState.classList.add('hidden');
                    renderResults(data, target);
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

    function renderResults(data, target) {
        resTarget.textContent = target;
        resTimestamp.textContent = new Date().toLocaleString('pt-BR');

        renderForms(data.scan_results.forms_found || []);
        renderVulnerabilities(data.scan_results.vulnerabilities || []);

        if (data.report_filename) {
            btnOpenReport.href = `/report/${data.report_filename}`;
            btnOpenReport.classList.remove('hidden');
        } else {
            btnOpenReport.classList.add('hidden');
        }

        if (data.ai_report) {
            aiReportContent.innerHTML = marked.parse(data.ai_report);
        } else {
            aiReportContent.innerHTML = '<p class="empty-message">Nenhum parecer técnico foi gerado pelo Gemini.</p>';
        }

        resultsState.classList.remove('hidden');
    }

    function renderForms(forms) {
        if (forms.length === 0) {
            formsContent.innerHTML = '<div class="empty-message">Nenhum formulário HTML com inputs elegíveis foi encontrado no alvo.</div>';
            return;
        }

        let html = '';
        forms.forEach(form => {
            const inputsHtml = (form.inputs || []).map(input => `<span class="form-input-badge">${escapeHTML(input)}</span>`).join('');
            html += `
                <div class="form-item">
                    <div class="form-item-header">
                        <span class="form-action">${escapeHTML(form.action)}</span>
                        <span class="form-method ${form.method}">${escapeHTML(form.method)}</span>
                    </div>
                    <div class="form-inputs-label">Campos de Entrada:</div>
                    <div class="form-inputs-list">
                        ${inputsHtml || '<span style="color:#6b7280; font-size:0.8rem;">(Nenhum input detectado)</span>'}
                    </div>
                </div>
            `;
        });
        formsContent.innerHTML = html;
    }

    function renderVulnerabilities(vulns) {
        if (vulns.length === 0) {
            vulnsContent.innerHTML = '<div class="empty-message" style="color: #10b981; font-style: normal; font-weight: 500;">✓ Nenhuma vulnerabilidade de SQL Injection foi identificada no alvo.</div>';
            return;
        }

        let html = '';
        vulns.forEach(vuln => {
            html += `
                <div class="vuln-item">
                    <div class="vuln-header">
                        <span class="vuln-title">${escapeHTML(vuln.vulnerability_type || 'SQL Injection')}</span>
                        <div class="vuln-meta">
                            <span class="badge badge-danger">${escapeHTML(vuln.type)}</span>
                            <span class="badge badge-warning">${escapeHTML(vuln.db_engine || 'Detectado')}</span>
                        </div>
                    </div>
                    <div class="vuln-details">
                        <div class="vuln-detail-row">
                            <div class="vuln-detail-label">Parâmetro:</div>
                            <div class="vuln-detail-value" style="color: #ffcc80;">${escapeHTML(vuln.parameter)}</div>
                        </div>
                        <div class="vuln-detail-row">
                            <div class="vuln-detail-label">Carga Útil:</div>
                            <div class="vuln-detail-value">${escapeHTML(vuln.payload)}</div>
                        </div>
                        ${vuln.error_signature ? `
                        <div class="vuln-detail-row">
                            <div class="vuln-detail-label">Erro Retornado:</div>
                            <div class="vuln-detail-value" style="color: #fca5a5; font-style: italic;">"${escapeHTML(vuln.error_signature)}"</div>
                        </div>
                        ` : ''}
                        <div class="vuln-detail-row">
                            <div class="vuln-detail-label">URL de Teste:</div>
                            <div class="vuln-detail-value" style="font-size:0.8rem; word-break:break-all;">${escapeHTML(vuln.url_tested || vuln.action || '')}</div>
                        </div>
                    </div>
                </div>
            `;
        });
        vulnsContent.innerHTML = html;
    }

    function escapeHTML(str) {
        if (!str) return '';
        return str.replace(/[&<>'"]/g, 
            tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                "'": '&#39;',
                '"': '&quot;'
            }[tag] || tag)
        );
    }
});
