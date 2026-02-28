const Components = {

    // --- Threat Badges & Severity Colors ---
    getRiskColorClass(level) {
        if (!level) return 'badge-safe';
        switch (level.toLowerCase()) {
            case 'safe': return 'badge-safe';
            case 'low': return 'badge-low';
            case 'medium': return 'badge-medium';
            case 'high': return 'badge-critical';
            case 'critical': return 'badge-critical';
            default: return 'badge-safe';
        }
    },

    getRiskIcon(level) {
        if (!level || level.toLowerCase() === 'safe') {
            return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
        }
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    },

    // --- Shared Results Generator ---
    generateScanResults(type, data) {
        const container = document.createElement('div');
        container.className = 'scan-results-container animate-fade-in mt-6';

        // 1. Top Summary Card
        const summaryCard = document.createElement('div');
        summaryCard.className = `panel risk-summary ${this.getRiskColorClass(data.risk_level)}`;

        summaryCard.innerHTML = `
            <div class="risk-header">
                <div class="risk-icon">${this.getRiskIcon(data.risk_level)}</div>
                <div>
                    <h2>${data.risk_level} Risk Detected</h2>
                    <p>${type.toUpperCase()} Scan Complete</p>
                </div>
                <div class="score-ring ml-auto hidden-sm">
                    <span class="score-val">${data.risk_score || data.scam_probability || 0}<small>/100</small></span>
                </div>
            </div>
            ${data.explanation ? `<div class="risk-explanation mt-4 p-4" style="background: rgba(0,0,0,0.1); border-radius: var(--radius-sm); border-left: 4px solid currentColor;">
                <p>${data.explanation.what_happened || ''} ${data.explanation.what_it_means || ''}</p>
                ${data.explanation.what_to_do && data.explanation.what_to_do.length ? `<p style="margin-top:0.5rem;font-weight:600;">Recommended actions:</p><ul style="margin:0.25rem 0 0 1.2rem">${data.explanation.what_to_do.map(a => `<li>${a}</li>`).join('')}</ul>` : ''}
            </div>` : ''}
            ${data.recommendation ? `<p class="mt-4 text-strong">Recommended Action: ${data.recommendation}</p>` : ''}
        `;

        container.appendChild(summaryCard);

        // 2. Findings Table (VirusTotal-style)
        const findings = data.findings || [];
        if (findings.length > 0) {
            const findingsPanel = document.createElement('div');
            findingsPanel.className = 'panel col-span-full mt-6';

            // Count flagged vs clean
            const flagged = findings.filter(f => (f.risk_contribution || 0) > 0).length;
            const clean = findings.length - flagged;

            findingsPanel.innerHTML = `
                <div class="panel-header" style="display:flex;justify-content:space-between;align-items:center;">
                    <h2>Security Analysis</h2>
                    <span style="font-size:0.85rem;opacity:0.7;">
                        ${flagged > 0
                    ? `<span style="color:var(--color-critical,#ef4444);font-weight:600;">${flagged} flagged</span> / ${clean} clean`
                    : `<span style="color:var(--color-safe,#22c55e);font-weight:600;">${clean} checks clean</span>`
                }
                    </span>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Check</th>
                                <th>Status</th>
                                <th>Details</th>
                                <th style="text-align:right;">Risk</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${findings.map(f => {
                    const risk = f.risk_contribution || 0;
                    const detail = f.result || f.detail || f.description || '';
                    const checkName = f.check || f.category || 'Check';

                    let statusBadge, statusClass;
                    if (risk >= 15) {
                        statusBadge = 'Flagged';
                        statusClass = 'badge-critical';
                    } else if (risk >= 5) {
                        statusBadge = 'Warning';
                        statusClass = 'badge-medium';
                    } else if (risk > 0) {
                        statusBadge = 'Info';
                        statusClass = 'badge-medium';
                    } else {
                        statusBadge = 'Clean';
                        statusClass = 'badge-safe';
                    }

                    const checkLabel = f.vt_link
                        ? `<a href="${f.vt_link}" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline;text-underline-offset:3px;">${checkName} ↗</a>`
                        : checkName;

                    return `<tr>
                                    <td class="text-strong">${checkLabel}</td>
                                    <td><span class="badge ${statusClass}">${statusBadge}</span></td>
                                    <td style="font-size:0.85rem;max-width:400px;">${detail}</td>
                                    <td style="text-align:right;font-weight:600;${risk > 0 ? 'color:var(--color-critical,#ef4444);' : 'color:var(--color-safe,#22c55e);'}">${risk > 0 ? '+' + risk : '0'}</td>
                                </tr>`;
                }).join('')}
                        </tbody>
                    </table>
                </div>
            `;
            container.appendChild(findingsPanel);
        }

        // 3. Domain Info Card (for URL scans)
        if (data.domain_info) {
            const infoPanel = document.createElement('div');
            infoPanel.className = 'panel mt-6';
            const di = data.domain_info;
            infoPanel.innerHTML = `
                <div class="panel-header"><h2>Domain Information</h2></div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;padding:0.5rem 0;">
                    ${di.registered_domain ? `<div><div class="label">Registered Domain</div><div class="value text-strong">${di.registered_domain}</div></div>` : ''}
                    ${di.subdomain ? `<div><div class="label">Subdomain</div><div class="value">${di.subdomain}</div></div>` : ''}
                    ${di.tld ? `<div><div class="label">TLD</div><div class="value">.${di.tld}</div></div>` : ''}
                    ${di.scheme ? `<div><div class="label">Protocol</div><div class="value">${di.scheme.toUpperCase()}</div></div>` : ''}
                    ${di.path && di.path !== '/' ? `<div><div class="label">Path</div><div class="value code-font" style="font-size:0.8rem;word-break:break-all;">${di.path}</div></div>` : ''}
                </div>
            `;
            container.appendChild(infoPanel);
        }

        // 4. Legacy Details Grid (for any scan type that uses data.details)
        if (data.details) {
            const grid = document.createElement('div');
            grid.className = 'results-grid mt-6';
            for (const [key, val] of Object.entries(data.details)) {
                if (typeof val === 'object' && val !== null) {
                    const subGrid = document.createElement('div');
                    subGrid.className = 'panel col-span-full';
                    subGrid.innerHTML = `<h3>${this.formatCheckName(key)}</h3>`;
                    const list = document.createElement('ul');
                    list.className = 'check-list';
                    for (const [subKey, subVal] of Object.entries(val)) {
                        const isFlagged = subVal === true || (typeof subVal === 'string' && subVal.toLowerCase() === 'high');
                        const statusClass = isFlagged ? 'text-critical text-strong' : 'text-safe';
                        const icon = isFlagged ? '❌' : '✅';
                        list.innerHTML += `<li><span>${icon} ${this.formatCheckName(subKey)}</span><span class="${statusClass}">${subVal}</span></li>`;
                    }
                    subGrid.appendChild(list);
                    grid.appendChild(subGrid);
                } else {
                    const card = document.createElement('div');
                    card.className = 'info-card panel';
                    let displayVal = val;
                    if (typeof val === 'boolean') {
                        displayVal = val ? '<span class="text-critical text-strong">Flags Detected</span>' : '<span class="text-safe">Clean</span>';
                    }
                    if (typeof val === 'string' && val.length > 50) {
                        card.classList.add('col-span-full');
                        displayVal = `<div class="code-block">${val}</div>`;
                    }
                    card.innerHTML = `<div class="label">${this.formatCheckName(key)}</div><div class="value">${displayVal}</div>`;
                    grid.appendChild(card);
                }
            }
            container.appendChild(grid);
        }

        return container;
    },

    // --- Network specific generators ---
    generateNetworkMap(data) {
        const wrapper = document.createElement('div');
        wrapper.className = 'animate-fade-in';

        // Normalize risk level from backend (uppercase) for display
        const overallRisk = data.risk_level || 'Unknown';
        const overallRiskUpper = overallRisk.toUpperCase();

        // Stats Header
        wrapper.innerHTML = `
            <div class="dashboard-grid mb-6">
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>Devices Discovered</h3>
                        <div class="stat-value">${data.devices ? data.devices.length : 0}</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>Total Open Ports</h3>
                        <div class="stat-value">${data.open_ports_total || 0}</div>
                    </div>
                </div>
                <div class="stat-card ${overallRiskUpper === 'HIGH' || overallRiskUpper === 'CRITICAL' ? 'alert text-critical' : ''}">
                    <div class="stat-info">
                        <h3>Highest Network Risk</h3>
                        <div class="stat-value">${overallRisk}</div>
                    </div>
                </div>
            </div>
        `;

        if (!data.devices || data.devices.length === 0) {
            wrapper.innerHTML += `<div class="panel empty-state">No devices found on the current subnet.</div>`;
            return wrapper;
        }

        // ── Visual Network Topology Map ──
        const topoPanel = document.createElement('div');
        topoPanel.className = 'panel col-span-full mb-6';
        topoPanel.innerHTML = `<div class="panel-header"><h2>Network Topology</h2></div>`;

        const svgW = 700, svgH = 420;
        const cx = svgW / 2, cy = svgH / 2;
        const topoRadius = Math.min(svgW, svgH) * 0.34;

        const riskColor = (level) => {
            const l = (level || '').toUpperCase();
            if (l === 'CRITICAL') return '#ef4444';
            if (l === 'HIGH') return '#f97316';
            if (l === 'MEDIUM') return '#eab308';
            return '#22c55e';
        };

        const routerIcon = `<path d="M-8,-6 h16 a2,2 0 0 1 2,2 v8 a2,2 0 0 1 -2,2 h-16 a2,2 0 0 1 -2,-2 v-8 a2,2 0 0 1 2,-2 z" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="-4" cy="0" r="1.5" fill="currentColor"/><circle cx="0" cy="0" r="1.5" fill="currentColor"/><circle cx="4" cy="0" r="1.5" fill="currentColor"/>`;
        const pcIcon = `<rect x="-8" y="-7" width="16" height="11" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="-4" y1="4" x2="4" y2="4" stroke="currentColor" stroke-width="1.5"/><line x1="0" y1="4" x2="0" y2="7" stroke="currentColor" stroke-width="1.5"/><line x1="-5" y1="7" x2="5" y2="7" stroke="currentColor" stroke-width="1.5"/>`;

        let svgContent = '';
        const devices = data.devices;
        const angleStep = (2 * Math.PI) / devices.length;

        // Connection lines
        devices.forEach((dev, i) => {
            const angle = angleStep * i - Math.PI / 2;
            const dx = cx + topoRadius * Math.cos(angle);
            const dy = cy + topoRadius * Math.sin(angle);
            const color = riskColor(dev.risk_level || dev.risk);
            svgContent += `<line x1="${cx}" y1="${cy}" x2="${dx}" y2="${dy}" stroke="${color}" stroke-width="2" stroke-dasharray="6 3" opacity="0.5"><animate attributeName="stroke-dashoffset" from="0" to="-18" dur="2s" repeatCount="indefinite"/></line>`;
        });

        // Gateway node at center
        const gwIp = data.network_info ? data.network_info.gateway : 'Gateway';
        svgContent += `
            <g transform="translate(${cx},${cy})" style="cursor:pointer">
                <circle r="32" fill="#1e293b" stroke="#3b82f6" stroke-width="2.5"/>
                <g transform="translate(0,-2)" style="color:#3b82f6">${routerIcon}</g>
                <text y="18" text-anchor="middle" fill="#94a3b8" font-size="8" font-family="Inter,sans-serif">${gwIp}</text>
                <text y="-22" text-anchor="middle" fill="#3b82f6" font-size="9" font-weight="600" font-family="Inter,sans-serif">Router</text>
            </g>`;

        // Device nodes
        devices.forEach((dev, i) => {
            const angle = angleStep * i - Math.PI / 2;
            const dx = cx + topoRadius * Math.cos(angle);
            const dy = cy + topoRadius * Math.sin(angle);
            const color = riskColor(dev.risk_level || dev.risk);
            const label = dev.device_type || dev.hostname || 'Device';
            const shortLabel = label.length > 14 ? label.slice(0, 12) + '...' : label;
            const portCount = dev.open_ports ? dev.open_ports.length : 0;

            svgContent += `
                <g transform="translate(${dx},${dy})" style="cursor:pointer">
                    <circle r="28" fill="#1e293b" stroke="${color}" stroke-width="2"/>
                    <g transform="translate(0,-4)" style="color:${color}">${pcIcon}</g>
                    <text y="14" text-anchor="middle" fill="${color}" font-size="8" font-weight="600" font-family="Inter,sans-serif">${shortLabel}</text>
                    <text y="23" text-anchor="middle" fill="#94a3b8" font-size="7" font-family="JetBrains Mono,monospace">${dev.ip}</text>
                    ${portCount > 0 ? `<circle cx="18" cy="-18" r="8" fill="${color}"/><text x="18" y="-15" text-anchor="middle" fill="#fff" font-size="8" font-weight="700" font-family="Inter,sans-serif">${portCount}</text>` : ''}
                </g>`;
        });

        const svgEl = document.createElement('div');
        svgEl.style.cssText = 'display:flex;justify-content:center;padding:1.5rem 0;overflow-x:auto;';
        svgEl.innerHTML = `<svg viewBox="0 0 ${svgW} ${svgH}" width="100%" style="max-width:${svgW}px;max-height:${svgH}px;" xmlns="http://www.w3.org/2000/svg">${svgContent}</svg>`;
        topoPanel.appendChild(svgEl);
        wrapper.appendChild(topoPanel);

        // ── Devices Table ──
        const tablePanel = document.createElement('div');
        tablePanel.className = 'panel col-span-full';
        tablePanel.innerHTML = `
            <div class="panel-header"><h2>Device Inventory & Port Scans</h2></div>
            <div class="table-responsive">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Device</th>
                            <th>Open Ports</th>
                            <th>Status/Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.devices.map(dev => {
            const hasPorts = dev.open_ports && dev.open_ports.length > 0;
            const riskLevel = (dev.risk_level || dev.risk || 'LOW').toUpperCase();
            const riskClass = riskLevel === 'HIGH' || riskLevel === 'CRITICAL' ? 'badge-critical' : (riskLevel === 'MEDIUM' ? 'badge-medium' : 'badge-safe');

            // Use device_type + hostname for the "Device" column
            const deviceLabel = dev.device_type || dev.hostname || dev.vendor || 'Unknown';

            // Format ports
            let portHtml = '<span class="text-muted">None</span>';
            if (hasPorts) {
                portHtml = dev.open_ports.map(p => `
                                    <div style="font-size: 0.8rem; margin-bottom: 2px;">
                                        <strong>${p.port}</strong> <span class="text-muted">(${p.service || 'unknown'})</span>
                                    </div>
                                `).join('');
            }

            return `
                                <tr>
                                    <td class="text-strong">${dev.ip}</td>
                                    <td class="code-font">${dev.mac || 'Unknown'}</td>
                                    <td>${deviceLabel}${dev.hostname && dev.device_type ? ' <span class="text-muted">(' + dev.hostname + ')</span>' : ''}</td>
                                    <td>${portHtml}</td>
                                    <td><span class="badge ${riskClass}">${riskLevel}</span></td>
                                </tr>
                            `;
        }).join('')}
                    </tbody>
                </table>
            </div>
        `;

        wrapper.appendChild(tablePanel);
        return wrapper;
    },

    // --- Helpers ---
    formatCheckName(key) {
        return key.replace(/_/g, ' ')
            .replace(/([A-Z])/g, ' $1')
            .replace(/^./, str => str.toUpperCase())
            .trim();
    }
};
