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
                    <span class="score-val">${data.risk_score || 0}<small>/100</small></span>
                </div>
            </div>
            ${data.explanation ? `<div class="risk-explanation mt-4 p-4" style="background: rgba(0,0,0,0.1); border-radius: var(--radius-sm); border-left: 4px solid currentColor;">${data.explanation}</div>` : ''}
            ${data.recommendation ? `<p class="mt-4 text-strong">Recommended Action: ${data.recommendation}</p>` : ''}
        `;

        container.appendChild(summaryCard);

        // 2. Details Grid
        const grid = document.createElement('div');
        grid.className = 'results-grid mt-6';

        if (data.details) {
            // Loop through detail checks and create cards
            for (const [key, val] of Object.entries(data.details)) {
                if (typeof val === 'object' && val !== null) {
                    // Extract heuristics or deeper objects
                    const subGrid = document.createElement('div');
                    subGrid.className = 'panel col-span-full';
                    subGrid.innerHTML = `<h3>${this.formatCheckName(key)}</h3>`;
                    
                    const list = document.createElement('ul');
                    list.className = 'check-list';
                    
                    for (const [subKey, subVal] of Object.entries(val)) {
                        const isFlagged = subVal === true || (typeof subVal === 'string' && subVal.toLowerCase() === 'high');
                        const statusClass = isFlagged ? 'text-critical text-strong' : 'text-safe';
                        const icon = isFlagged ? '❌' : '✅';
                        
                        list.innerHTML += `
                            <li>
                                <span>${icon} ${this.formatCheckName(subKey)}</span>
                                <span class="${statusClass}">${subVal}</span>
                            </li>
                        `;
                    }
                    subGrid.appendChild(list);
                    grid.appendChild(subGrid);
                } else {
                    // Simple KPI Card
                    const card = document.createElement('div');
                    card.className = 'info-card panel';
                    
                    let displayVal = val;
                    if (typeof val === 'boolean') {
                        displayVal = val ? '<span class="text-critical text-strong">Flags Detected</span>' : '<span class="text-safe">Clean</span>';
                    }

                    // Format large text blocks (like email body excerpts)
                    if (typeof val === 'string' && val.length > 50) {
                        card.classList.add('col-span-full');
                        displayVal = `<div class="code-block">${val}</div>`;
                    }

                    card.innerHTML = `
                        <div class="label">${this.formatCheckName(key)}</div>
                        <div class="value">${displayVal}</div>
                    `;
                    grid.appendChild(card);
                }
            }
        }

        container.appendChild(grid);
        return container;
    },

    // --- Network specific generators ---
    generateNetworkMap(data) {
        const wrapper = document.createElement('div');
        wrapper.className = 'animate-fade-in';

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
                        <div class="stat-value">${data.total_open_ports || 0}</div>
                    </div>
                </div>
                <div class="stat-card ${data.highest_risk === 'High' ? 'alert text-critical' : ''}">
                    <div class="stat-info">
                        <h3>Highest Network Risk</h3>
                        <div class="stat-value">${data.highest_risk || 'Unknown'}</div>
                    </div>
                </div>
            </div>
        `;

        if (!data.devices || data.devices.length === 0) {
            wrapper.innerHTML += `<div class="panel empty-state">No devices found on the current subnet.</div>`;
            return wrapper;
        }

        // Devices Table
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
                            <th>Vendor</th>
                            <th>Open Ports</th>
                            <th>Status/Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.devices.map(dev => {
                            const hasPorts = dev.open_ports && dev.open_ports.length > 0;
                            const riskClass = dev.risk === 'High' ? 'badge-critical' : (dev.risk === 'Medium' ? 'badge-medium' : 'badge-safe');
                            
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
                                    <td class="code-font">${dev.mac}</td>
                                    <td>${dev.vendor}</td>
                                    <td>${portHtml}</td>
                                    <td><span class="badge ${riskClass}">${dev.risk}</span></td>
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
