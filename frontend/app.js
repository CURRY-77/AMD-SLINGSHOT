const API_BASE = '/api';

const app = {
    currentView: 'dashboard',

    // Packet monitor state
    monitorInterval: null,
    trafficChart: null,
    monitorActive: false,
    chartDataX: [],
    chartDataY: [],

    init() {
        this.setupNavigation();
        this.setupTheme();
        this.setupForms();
        this.loadDashboardStats();
        this.initTrafficChart();

        // Check if there's a hash in URL to load specific view
        const hash = window.location.hash.substring(1);
        if (hash) {
            this.switchView(hash);
        }
    },

    // --- UI & Lifecycle ---

    setupNavigation() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const viewId = e.currentTarget.dataset.view;
                this.switchView(viewId);
                // Update URL without scrolling
                history.pushState(null, null, `#${viewId}`);
            });
        });
    },

    setupTheme() {
        const toggleBtn = document.getElementById('theme-toggle');
        const sun = toggleBtn.querySelector('.sun-icon');
        const moon = toggleBtn.querySelector('.moon-icon');

        // Check saved theme
        const savedTheme = localStorage.getItem('kalpana-theme') || 'theme-light';
        document.body.className = savedTheme;

        if (savedTheme === 'theme-dark') {
            sun.style.display = 'none';
            moon.style.display = 'block';
        }

        toggleBtn.addEventListener('click', () => {
            const isDark = document.body.classList.contains('theme-dark');
            if (isDark) {
                document.body.className = 'theme-light';
                localStorage.setItem('kalpana-theme', 'theme-light');
                sun.style.display = 'block';
                moon.style.display = 'none';
            } else {
                document.body.className = 'theme-dark';
                localStorage.setItem('kalpana-theme', 'theme-dark');
                sun.style.display = 'none';
                moon.style.display = 'block';
            }
            if (this.trafficChart) this.trafficChart.update();
        });
    },

    switchView(viewId) {
        // Update Nav
        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
        const navTarget = document.querySelector(`.nav-item[data-view="${viewId}"]`);
        if (navTarget) navTarget.classList.add('active');

        // Update Views
        document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
        const viewTarget = document.getElementById(`view-${viewId}`);
        if (viewTarget) viewTarget.classList.add('active');

        this.currentView = viewId;

        // Auto-refresh dashboard if we navigate to it
        if (viewId === 'dashboard') {
            this.loadDashboardStats();
        }
    },

    // --- Forms & Actions ---

    setupForms() {
        // URL Scanner
        document.getElementById('form-url-scan').addEventListener('submit', (e) => {
            e.preventDefault();
            this.scanUrl();
        });

        // Email Scanner
        document.getElementById('form-email-scan').addEventListener('submit', (e) => {
            e.preventDefault();
            this.scanEmail();
        });

        // File Analyzer Setup
        const dropzone = document.getElementById('file-dropzone');
        const fileInput = document.getElementById('input-file');

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'var(--accent-blue)';
            dropzone.style.background = 'rgba(59, 130, 246, 0.05)';
        });

        dropzone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'var(--border-color)';
            dropzone.style.background = 'transparent';
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'var(--border-color)';
            dropzone.style.background = 'transparent';

            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                this.handleFileSelection(fileInput.files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) {
                this.handleFileSelection(e.target.files[0]);
            }
        });

        document.getElementById('btn-scan-file').addEventListener('click', () => {
            this.scanFile();
        });

        // Network Map
        document.getElementById('btn-scan-network').addEventListener('click', () => {
            this.scanNetwork();
        });

        // Packet Monitor
        document.getElementById('btn-toggle-monitor').addEventListener('click', () => {
            this.togglePacketMonitor();
        });
    },

    handleFileSelection(file) {
        if (!file) return;
        document.querySelector('.dropzone-content').classList.add('hidden');
        document.getElementById('file-selection-display').classList.remove('hidden');
        document.getElementById('selected-filename').textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    },

    clearFileSelection() {
        document.getElementById('input-file').value = '';
        document.querySelector('.dropzone-content').classList.remove('hidden');
        document.getElementById('file-selection-display').classList.add('hidden');
        // Clear previous results if any
        const container = document.getElementById('view-file-analyzer');
        const prevResults = container.querySelector('.scan-results-container');
        if (prevResults) prevResults.remove();
    },

    showLoader(containerId) {
        const c = document.getElementById(containerId);
        const l = c.querySelector('.scan-loading');
        if (l) l.classList.remove('hidden');

        // Remove old results
        const oldResults = c.querySelector('.scan-results-container, .results-grid, .scan-results');
        if (oldResults) oldResults.remove();
    },

    hideLoader(containerId) {
        const c = document.getElementById(containerId);
        const l = c.querySelector('.scan-loading');
        if (l) l.classList.add('hidden');
    },

    // --- API Interactions ---

    async loadDashboardStats() {
        try {
            const res = await fetch(`${API_BASE}/history?limit=10`);
            const raw = await res.json();

            // API returns a plain array; normalize
            const history = Array.isArray(raw) ? raw : (raw.history || []);

            // Tally counts (backend uses scan_type, not type)
            let urls = 0, emails = 0, files = 0, threats = 0;
            history.forEach(item => {
                const t = (item.scan_type || item.type || '').toLowerCase();
                if (t === 'url') urls++;
                if (t === 'email') emails++;
                if (t === 'file') files++;
                if (item.risk_level === 'HIGH' || item.risk_level === 'CRITICAL') threats++;
            });

            document.getElementById('dashboard-url-count').textContent = urls;
            document.getElementById('dashboard-email-count').textContent = emails;
            document.getElementById('dashboard-file-count').textContent = files;
            document.getElementById('dashboard-threat-count').textContent = threats;

            const tbody = document.getElementById('dashboard-history-list');
            if (history.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No recent scans found.</td></tr>';
                return;
            }

            tbody.innerHTML = history.map(item => {
                const scanType = item.scan_type || item.type || 'Unknown';
                const ts = item.created_at || item.timestamp;
                return `
                <tr>
                    <td>${ts ? new Date(ts).toLocaleTimeString() : '—'}</td>
                    <td><span class="badge ${scanType.toLowerCase() === 'url' ? 'badge-info' : 'badge-low'}">${scanType}</span></td>
                    <td class="truncate" style="max-width: 200px;" title="${item.target}">${item.target}</td>
                    <td><span class="badge ${item.risk_level === 'HIGH' || item.risk_level === 'CRITICAL' ? 'badge-critical' : (item.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-safe')}">${item.risk_level}</span></td>
                    <td><button class="btn btn-secondary btn-sm" onclick="app.viewHistoryDetails('${item.id}')">View</button></td>
                </tr>`;
            }).join('');

        } catch (err) {
            console.error('Failed to load dashboard:', err);
        }
    },

    async scanUrl() {
        const url = document.getElementById('input-url').value;
        if (!url) return;

        this.showLoader('view-url-scanner');
        document.getElementById('btn-scan-url').disabled = true;

        try {
            const response = await fetch(`${API_BASE}/scan/url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await response.json();

            this.hideLoader('view-url-scanner');
            document.getElementById('view-url-scanner').appendChild(Components.generateScanResults('url', data));

        } catch (err) {
            alert('Error scanning URL: ' + err.message);
            this.hideLoader('view-url-scanner');
        } finally {
            document.getElementById('btn-scan-url').disabled = false;
        }
    },

    async scanEmail() {
        const body = document.getElementById('input-email-body').value;
        const sender = document.getElementById('input-email-sender').value;
        const subject = document.getElementById('input-email-subject').value;

        if (!body) return;

        const btn = document.getElementById('btn-scan-email');
        btn.disabled = true;
        btn.textContent = 'Scanning...';

        // Remove old results
        const c = document.getElementById('view-email-scanner');
        const old = c.querySelector('.scan-results-container');
        if (old) old.remove();

        try {
            const response = await fetch(`${API_BASE}/scan/email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: body, sender, subject })
            });
            const data = await response.json();

            c.appendChild(Components.generateScanResults('email', data));

        } catch (err) {
            alert('Error scanning Email: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Analyze Email';
        }
    },

    async scanFile() {
        const fileInput = document.getElementById('input-file');
        const file = fileInput.files[0];
        if (!file) return;

        const btn = document.getElementById('btn-scan-file');
        btn.disabled = true;
        btn.textContent = 'Analyzing Metadata & Hashes...';

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`${API_BASE}/scan/file`, {
                method: 'POST',
                body: formData
            });
            const data = await response.json();

            document.getElementById('view-file-analyzer').appendChild(Components.generateScanResults('file', data));

        } catch (err) {
            alert('Error scanning file: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Analyze File';
        }
    },

    async scanNetwork() {
        this.showLoader('view-network-map');
        const btn = document.getElementById('btn-scan-network');
        btn.disabled = true;

        try {
            const response = await fetch(`${API_BASE}/scan/network`, { method: 'POST' });
            const data = await response.json();

            this.hideLoader('view-network-map');

            const container = document.getElementById('network-results-container');
            container.innerHTML = '';
            container.appendChild(Components.generateNetworkMap(data));

        } catch (err) {
            alert('Error mapping network: ' + err.message);
            this.hideLoader('view-network-map');
        } finally {
            btn.disabled = false;
        }
    },

    async viewHistoryDetails(id) {
        try {
            const response = await fetch(`${API_BASE}/history`);
            const raw = await response.json();
            const history = Array.isArray(raw) ? raw : (raw.history || []);
            const item = history.find(i => String(i.id) === String(id));

            if (item) {
                const scanType = item.scan_type || item.type || 'Scan';
                document.getElementById('modal-title').textContent = `${scanType} Scan: ${item.target}`;
                document.getElementById('modal-content').textContent = JSON.stringify(item.details || item, null, 2);
                document.getElementById('json-modal').classList.add('show');
            }
        } catch (e) { console.error(e); }
    },

    closeModal() {
        document.getElementById('json-modal').classList.remove('show');
    },

    // --- Packet Monitor ---

    initTrafficChart() {
        const ctx = document.getElementById('trafficChart').getContext('2d');

        // Chart.js defaults for theme matching
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = 'Inter';

        this.trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.chartDataX,
                datasets: [{
                    label: 'Packets/sec',
                    data: this.chartDataY,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    },

    togglePacketMonitor() {
        const btn = document.getElementById('btn-toggle-monitor');
        const badge = document.getElementById('monitor-status');

        if (this.monitorActive) {
            // Stop
            clearInterval(this.monitorInterval);
            this.monitorActive = false;
            btn.textContent = 'Start Monitor';
            btn.classList.replace('btn-secondary', 'btn-primary');
            badge.textContent = 'Inactive';
            badge.className = 'status-badge';
        } else {
            // Start
            this.monitorActive = true;
            btn.textContent = 'Stop Monitor';
            btn.classList.replace('btn-primary', 'btn-secondary');
            badge.textContent = 'Active - Live';
            badge.className = 'status-badge active pulse';

            // Clear chart data in-place (preserve Chart.js reference)
            this.chartDataX.length = 0;
            this.chartDataY.length = 0;
            this.trafficChart.data.labels = this.chartDataX;
            this.trafficChart.data.datasets[0].data = this.chartDataY;
            this.trafficChart.update();

            this.pollPacketMonitor();
            this.monitorInterval = setInterval(() => this.pollPacketMonitor(), 1000);
        }
    },

    async pollPacketMonitor() {
        try {
            const response = await fetch(`${API_BASE}/monitor/snapshot`);
            const data = await response.json();

            // Use traffic_stats for packet counts
            const stats = data.traffic_stats && data.traffic_stats[0] ? data.traffic_stats[0] : {};
            const totalSent = stats.packets_sent || 0;
            const totalRecv = stats.packets_recv || 0;

            // Update Totals
            document.getElementById('pm-total-sent').textContent = totalSent.toLocaleString();
            document.getElementById('pm-total-recv').textContent = totalRecv.toLocaleString();

            // Update Chart — use speed_down as a proxy for packets/sec activity
            const now = new Date().toLocaleTimeString([], { minute: '2-digit', second: '2-digit' });
            this.chartDataX.push(now);
            this.chartDataY.push(Math.round((stats.speed_up || 0) + (stats.speed_down || 0)));

            if (this.chartDataX.length > 60) {
                this.chartDataX.shift();
                this.chartDataY.shift();
            }

            this.trafficChart.update();

            // Update Alerts / Connections
            const alertsContainer = document.getElementById('monitor-alerts');
            const alerts = data.alerts || [];
            if (alerts.length > 0) {
                alertsContainer.innerHTML = alerts.map(a => `<div class="alert badge-critical mt-2">${a.message || a.description || JSON.stringify(a)}</div>`).join('');
            } else {
                alertsContainer.innerHTML = `<div class="alert badge-safe mt-2">No anomalies detected. Traffic is normal.</div>`;
            }

        } catch (e) {
            console.error("Packet monitor poll failed:", e);
        }
    }

};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => app.init());
