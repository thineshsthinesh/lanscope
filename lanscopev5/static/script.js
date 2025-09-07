class LanScopeAdvancedApp {
    constructor() {
        this.socket = io();
        this.cy = null;
        this.selectedNode = null;
        this.scanInProgress = false;
        this.currentScanConfig = null;
        this.networkStats = {
            totalDevices: 0,
            onlineDevices: 0,
            openPorts: 0,
            lastScan: null,
            subnetCoverage: 0,
            activeSubnets: 0
        };
        
        this.initializeElements();
        this.initializeCytoscape();
        this.setupSocketHandlers();
        this.setupEventListeners();
        this.loadCurrentNetworkInfo();
    }

    initializeElements() {
        this.elements = {
            // Status elements
            statusDot: document.getElementById('status-dot'),
            statusText: document.getElementById('status-text'),
            
            // Modal elements
            subnetModal: document.getElementById('subnet-modal'),
            closeModal: document.getElementById('close-modal'),
            subnetInput: document.getElementById('subnet-input'),
            subnetInfo: document.getElementById('subnet-info'),
            maxHosts: document.getElementById('max-hosts'),
            startScanBtn: document.getElementById('start-scan-btn'),
            cancelScanBtn: document.getElementById('cancel-scan-btn'),
            
            // Progress elements
            scanProgressSection: document.getElementById('scan-progress-section'),
            modalProgressFill: document.getElementById('modal-progress-fill'),
            hostsScanned: document.getElementById('hosts-scanned'),
            devicesFound: document.getElementById('devices-found'),
            currentSubnet: document.getElementById('current-subnet'),
            scanEta: document.getElementById('scan-eta'),
            
            // Control buttons
            configureScanBtn: document.getElementById('configure-scan-btn'),
            refreshBtn: document.getElementById('refresh-btn'),
            exportBtn: document.getElementById('export-btn'),
            
            // Graph controls
            zoomIn: document.getElementById('zoom-in'),
            zoomOut: document.getElementById('zoom-out'),
            center: document.getElementById('center'),
            fullscreen: document.getElementById('fullscreen'),
            
            // Device details
            deviceDetails: document.getElementById('device-details'),
            
            // Statistics
            totalDevices: document.getElementById('total-devices'),
            onlineDevices: document.getElementById('online-devices'),
            openPorts: document.getElementById('open-ports'),
            scanTime: document.getElementById('scan-time'),
            subnetCoverage: document.getElementById('subnet-coverage'),
            activeSubnets: document.getElementById('active-subnets'),
            
            // Network info
            currentNetwork: document.getElementById('current-network'),
            interfaceInfo: document.getElementById('interface-info'),
            scanDuration: document.getElementById('scan-duration'),
            bottomProgress: document.getElementById('bottom-progress'),
            bottomProgressFill: document.getElementById('bottom-progress-fill'),
            bottomProgressText: document.getElementById('bottom-progress-text')
        };
    }

    initializeCytoscape() {
        this.cy = cytoscape({
            container: document.getElementById('cy'),
            style: this.getCytoscapeStyles(),
            layout: {
                name: 'cose',
                animate: true,
                animationDuration: 1000,
                fit: true,
                padding: 50,
                nodeRepulsion: function(node) { 
                    return node.data('device_type') === 'gateway' ? 800000 : 400000; 
                },
                nodeOverlap: 20,
                idealEdgeLength: function(edge) { 
                    return edge.data('connection_type') === 'inter_subnet' ? 150 : 100; 
                },
                edgeElasticity: function(edge) { return 100; },
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            },
            wheelSensitivity: 0.2,
            minZoom: 0.1,
            maxZoom: 5
        });

        this.setupCytoscapeEvents();
    }

    getCytoscapeStyles() {
        return [
            {
                selector: 'node',
                style: {
                    'background-color': '#64748b',
                    'label': 'data(label)',
                    'color': '#f1f5f9',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'font-size': '10px',
                    'font-weight': '600',
                    'text-outline-color': 'rgba(0,0,0,0.9)',
                    'text-outline-width': 2,
                    'width': '35px',
                    'height': '35px',
                    'border-width': 2,
                    'border-color': 'rgba(255,255,255,0.2)',
                    'transition-property': 'background-color, border-color, width, height',
                    'transition-duration': '0.3s'
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-color': '#2563eb',
                    'border-width': 3,
                    'background-color': '#3b82f6'
                }
            },
            {
                selector: 'node:hover',
                style: {
                    'width': '40px',
                    'height': '40px',
                    'border-width': 3
                }
            },
            {
                selector: 'node[device_type="gateway"]',
                style: {
                    'background-color': '#2563eb',
                    'shape': 'diamond',
                    'width': '45px',
                    'height': '45px',
                    'border-color': '#60a5fa',
                    'font-size': '11px'
                }
            },
            {
                selector: 'node[status="up"]',
                style: {
                    'background-color': '#10b981',
                    'border-color': '#34d399'
                }
            },
            {
                selector: 'node[status="down"]',
                style: {
                    'background-color': '#ef4444',
                    'border-color': '#f87171'
                }
            },
            {
                selector: 'node[device_type="router"]',
                style: {
                    'shape': 'diamond',
                    'background-color': '#7c3aed',
                    'border-color': '#a78bfa',
                    'width': '40px',
                    'height': '40px'
                }
            },
            {
                selector: 'node[device_type="web_server"], node[device_type="linux_server"], node[device_type="windows_server"]',
                style: {
                    'shape': 'round-rectangle',
                    'background-color': '#f59e0b',
                    'border-color': '#fbbf24',
                    'width': '40px',
                    'height': '30px'
                }
            },
            {
                selector: 'node[device_type="printer"]',
                style: {
                    'shape': 'round-triangle',
                    'background-color': '#06b6d4',
                    'border-color': '#22d3ee'
                }
            },
            {
                selector: 'node[device_type="smart_device"], node[device_type="iot_device"]',
                style: {
                    'shape': 'pentagon',
                    'background-color': '#8b5cf6',
                    'border-color': '#a78bfa'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': 'rgba(100, 116, 139, 0.6)',
                    'target-arrow-color': 'rgba(100, 116, 139, 0.6)',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.7,
                    'transition-property': 'line-color, width, opacity',
                    'transition-duration': '0.3s'
                }
            },
            {
                selector: 'edge[connection_type="inter_subnet"]',
                style: {
                    'width': 3,
                    'line-color': '#2563eb',
                    'target-arrow-color': '#2563eb',
                    'line-style': 'dashed'
                }
            },
            {
                selector: 'edge[connection_type="subnet_local"]',
                style: {
                    'width': 2,
                    'line-color': '#10b981',
                    'target-arrow-color': '#10b981'
                }
            },
            {
                selector: 'edge:hover',
                style: {
                    'width': 4,
                    'line-color': '#2563eb',
                    'target-arrow-color': '#2563eb',
                    'opacity': 1
                }
            },
            {
                selector: 'edge.highlighted',
                style: {
                    'width': 4,
                    'line-color': '#10b981',
                    'target-arrow-color': '#10b981',
                    'opacity': 1
                }
            }
        ];
    }

    setupCytoscapeEvents() {
        this.cy.on('tap', 'node', (evt) => {
            const node = evt.target;
            this.selectNode(node);
        });

        this.cy.on('tap', (evt) => {
            if (evt.target === this.cy) {
                this.deselectNode();
            }
        });

        this.cy.on('mouseover', 'node', (evt) => {
            document.body.style.cursor = 'pointer';
        });

        this.cy.on('mouseout', 'node', (evt) => {
            document.body.style.cursor = 'default';
        });
    }

    setupSocketHandlers() {
        this.socket.on('connect', () => {
            console.log('Socket.IO connection established');
            this.updateConnectionStatus('connected');
        });

        this.socket.on('disconnect', () => {
            console.warn('Socket.IO connection lost');
            this.updateConnectionStatus('disconnected');
        });

        this.socket.on('update_graph', (data) => {
            console.log('Received graph update:', data);
            this.updateGraph(data);
        });

        this.socket.on('scan_progress', (data) => {
            console.log('Scan progress:', data);
            this.updateScanProgress(data);
        });

        this.socket.on('scan_started', (data) => {
            console.log('Scan started:', data);
            this.onScanStarted(data);
        });

        this.socket.on('scan_completed', (data) => {
            console.log('Scan completed:', data);
            this.onScanCompleted(data);
        });

        this.socket.on('scan_error', (data) => {
            console.error('Scan error:', data);
            this.onScanError(data);
        });

        this.socket.on('device_discovered', (data) => {
            console.log('Device discovered:', data);
            this.onDeviceDiscovered(data);
        });
    }

    setupEventListeners() {
        // Modal controls
        this.elements.configureScanBtn?.addEventListener('click', () => {
            this.showSubnetModal();
        });

        this.elements.closeModal?.addEventListener('click', () => {
            this.hideSubnetModal();
        });

        this.elements.subnetModal?.addEventListener('click', (e) => {
            if (e.target === this.elements.subnetModal) {
                this.hideSubnetModal();
            }
        });

        // Subnet input validation
        this.elements.subnetInput?.addEventListener('input', () => {
            this.validateSubnetInput();
        });

        // Preset buttons
        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const subnet = btn.dataset.subnet;
                this.elements.subnetInput.value = subnet;
                this.validateSubnetInput();
            });
        });

        // Scan type selection
        document.querySelectorAll('.option-card').forEach(card => {
            card.addEventListener('click', () => {
                document.querySelectorAll('.option-card').forEach(c => c.classList.remove('selected'));
                card.classList.add('selected');
            });
        });

        // Scan controls
        this.elements.startScanBtn?.addEventListener('click', () => {
            this.startCustomScan();
        });

        this.elements.cancelScanBtn?.addEventListener('click', () => {
            this.cancelScan();
        });

        this.elements.refreshBtn?.addEventListener('click', () => {
            this.quickRefresh();
        });

        this.elements.exportBtn?.addEventListener('click', () => {
            this.exportData();
        });

        // Graph controls
        this.elements.zoomIn?.addEventListener('click', () => {
            this.cy.zoom(this.cy.zoom() * 1.2);
            this.cy.center();
        });

        this.elements.zoomOut?.addEventListener('click', () => {
            this.cy.zoom(this.cy.zoom() * 0.8);
            this.cy.center();
        });

        this.elements.center?.addEventListener('click', () => {
            this.cy.fit();
        });

        this.elements.fullscreen?.addEventListener('click', () => {
            this.toggleFullscreen();
        });
    }

    async loadCurrentNetworkInfo() {
        try {
            const response = await fetch('/api/network-info');
            const data = await response.json();
            
            if (data.interface && data.subnet) {
                this.elements.currentNetwork.textContent = data.subnet;
                this.elements.interfaceInfo.textContent = data.interface;
                this.elements.subnetInput.value = data.subnet;
            }
        } catch (error) {
            console.warn('Failed to load network info:', error);
            this.elements.currentNetwork.textContent = 'Auto-detect failed';
        }
    }

    validateSubnetInput() {
        const subnet = this.elements.subnetInput.value.trim();
        const subnetRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
        
        if (!subnet) {
            this.elements.subnetInfo.textContent = 'Enter a subnet in CIDR notation (e.g., 192.168.0.0/16)';
            this.elements.subnetInfo.className = 'subnet-size-indicator';
            return false;
        }

        if (!subnetRegex.test(subnet)) {
            this.elements.subnetInfo.textContent = 'Invalid CIDR format. Use format: 192.168.0.0/24';
            this.elements.subnetInfo.className = 'subnet-size-indicator';
            this.elements.subnetInfo.style.color = 'var(--danger-color)';
            return false;
        }

        try {
            const [network, prefix] = subnet.split('/');
            const prefixNum = parseInt(prefix);
            
            if (prefixNum < 8 || prefixNum > 30) {
                this.elements.subnetInfo.textContent = 'Prefix must be between /8 and /30';
                this.elements.subnetInfo.style.color = 'var(--danger-color)';
                return false;
            }

            const hostBits = 32 - prefixNum;
            const maxHosts = Math.pow(2, hostBits) - 2;
            
            let sizeDescription = '';
            let warningColor = 'var(--text-secondary)';
            
            if (maxHosts <= 254) {
                sizeDescription = `Small network: ${maxHosts.toLocaleString()} possible hosts`;
            } else if (maxHosts <= 4094) {
                sizeDescription = `Medium network: ${maxHosts.toLocaleString()} possible hosts`;
                warningColor = 'var(--warning-color)';
            } else if (maxHosts <= 65534) {
                sizeDescription = `Large network: ${maxHosts.toLocaleString()} possible hosts`;
                warningColor = 'var(--warning-color)';
            } else {
                sizeDescription = `Very large network: ${maxHosts.toLocaleString()} possible hosts - Use intelligent scan!`;
                warningColor = 'var(--danger-color)';
            }
            
            this.elements.subnetInfo.textContent = sizeDescription;
            this.elements.subnetInfo.style.color = warningColor;
            
            // Update max hosts selector based on network size
            this.updateMaxHostsOptions(maxHosts);
            
            return true;
        } catch (error) {
            this.elements.subnetInfo.textContent = 'Invalid subnet format';
            this.elements.subnetInfo.style.color = 'var(--danger-color)';
            return false;
        }
    }

    updateMaxHostsOptions(maxPossibleHosts) {
        const select = this.elements.maxHosts;
        const options = [
            { value: 1000, label: '1,000 hosts (Fast)' },
            { value: 5000, label: '5,000 hosts (Balanced)' },
            { value: 10000, label: '10,000 hosts (Thorough)' },
            { value: 20000, label: '20,000 hosts (Extensive)' },
            { value: maxPossibleHosts, label: `All ${maxPossibleHosts.toLocaleString()} hosts (Full scan)` }
        ];

        select.innerHTML = '';
        options.forEach(option => {
            if (option.value <= maxPossibleHosts) {
                const optionElement = document.createElement('option');
                optionElement.value = option.value;
                optionElement.textContent = option.label;
                if (option.value === 5000 || (maxPossibleHosts < 5000 && option.value === maxPossibleHosts)) {
                    optionElement.selected = true;
                }
                select.appendChild(optionElement);
            }
        });
    }

    showSubnetModal() {
        this.elements.subnetModal.classList.add('active');
        this.validateSubnetInput();
    }

    hideSubnetModal() {
        this.elements.subnetModal.classList.remove('active');
        if (this.scanInProgress) {
            this.elements.scanProgressSection.classList.remove('active');
        }
    }

    async startCustomScan() {
        if (!this.validateSubnetInput() || this.scanInProgress) {
            return;
        }

        const subnet = this.elements.subnetInput.value.trim();
        const maxHosts = parseInt(this.elements.maxHosts.value);
        const scanType = document.querySelector('.option-card.selected').dataset.scanType;

        this.currentScanConfig = {
            subnet,
            maxHosts,
            scanType,
            startTime: Date.now()
        };

        // Show progress section
        this.elements.scanProgressSection.classList.add('active');
        this.elements.startScanBtn.disabled = true;
        this.elements.startScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

        try {
            const response = await fetch('/api/start-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(this.currentScanConfig)
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const result = await response.json();
            console.log('Custom scan started:', result);
            
        } catch (error) {
            console.error('Failed to start custom scan:', error);
            this.showNotification('Failed to start scan. Please check your network configuration.', 'error');
            this.resetScanUI();
        }
    }

    cancelScan() {
        if (this.scanInProgress) {
            this.socket.emit('cancel_scan');
        }
        this.hideSubnetModal();
        this.resetScanUI();
    }

    resetScanUI() {
        this.scanInProgress = false;
        this.elements.scanProgressSection.classList.remove('active');
        this.elements.startScanBtn.disabled = false;
        this.elements.startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        this.elements.bottomProgress.classList.remove('active');
    }

    async quickRefresh() {
        const btn = this.elements.refreshBtn;
        if (btn) {
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Scanning...';
            btn.disabled = true;

            try {
                const response = await fetch('/api/start-scan', { method: 'POST' });
                if (response.ok) {
                    console.log('Quick refresh started');
                }
            } catch (error) {
                console.error('Quick refresh failed:', error);
            }

            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.disabled = false;
            }, 3000);
        }
    }

    onScanStarted(data) {
        this.scanInProgress = true;
        this.elements.bottomProgress.classList.add('active');
        this.elements.currentNetwork.textContent = data.subnet || 'Scanning...';
        
        if (data.total_hosts) {
            this.elements.bottomProgressText.textContent = `Scanning ${data.total_hosts.toLocaleString()} hosts...`;
        }
    }

    onScanCompleted(data) {
        this.scanInProgress = false;
        this.resetScanUI();
        
        // Update statistics
        if (data.duration) {
            this.elements.scanDuration.textContent = `${Math.round(data.duration)}s`;
        }

        // Update network statistics
        this.updateNetworkStatistics(data);

        // Show completion notification
        this.showNotification('Scan completed successfully!', 'success');
        
        console.log('Scan completed with stats:', data);
    }

    onScanError(data) {
        this.resetScanUI();
        this.showNotification(`Scan failed: ${data.error}`, 'error');
        console.error('Scan error:', data);
    }

    onDeviceDiscovered(data) {
        // Optional: Show toast notifications for interesting devices
        if (data.device_type && ['web_server', 'router', 'gateway'].includes(data.device_type)) {
            console.log(`Discovered ${data.device_type} at ${data.ip}`);
        }
    }

    updateScanProgress(data) {
        if (!this.scanInProgress) return;

        const progressPct = data.progress_percentage || 0;
        
        // Update modal progress
        if (this.elements.modalProgressFill) {
            this.elements.modalProgressFill.style.width = `${progressPct}%`;
        }
        
        // Update bottom progress
        if (this.elements.bottomProgressFill) {
            this.elements.bottomProgressFill.style.width = `${progressPct}%`;
        }

        // Update progress stats
        if (data.hosts_scanned !== undefined) {
            this.elements.hostsScanned.textContent = data.hosts_scanned.toLocaleString();
        }
        
        if (data.devices_found !== undefined) {
            this.elements.devicesFound.textContent = data.devices_found.toLocaleString();
        }
        
        if (data.subnet) {
            this.elements.currentSubnet.textContent = data.subnet;
        }

        // Calculate ETA
        if (this.currentScanConfig && data.hosts_scanned && data.total_hosts) {
            const elapsed = (Date.now() - this.currentScanConfig.startTime) / 1000;
            const hostsPerSecond = data.hosts_scanned / elapsed;
            const remaining = data.total_hosts - data.hosts_scanned;
            const eta = remaining / hostsPerSecond;
            
            if (eta > 0 && eta < 3600) {
                this.elements.scanEta.textContent = `${Math.round(eta)}s`;
            }
        }

        // Update bottom progress text
        if (data.message) {
            this.elements.bottomProgressText.textContent = data.message;
        }
    }

    updateConnectionStatus(status) {
        const statusMap = {
            'connected': { class: 'connected', text: 'Connected' },
            'connecting': { class: 'connecting', text: 'Connecting...' },
            'disconnected': { class: 'disconnected', text: 'Disconnected' }
        };

        const config = statusMap[status];
        if (config && this.elements.statusDot && this.elements.statusText) {
            this.elements.statusDot.className = `status-dot ${config.class}`;
            this.elements.statusText.textContent = config.text;
        }
    }

    updateGraph(elements) {
        if (!Array.isArray(elements)) {
            console.error('Received non-array data for graph update:', elements);
            return;
        }

        let wasNodeAdded = false;
        
        elements.forEach(element => {
            const id = element.data?.id;
            if (!id) return;

            const existingElement = this.cy.getElementById(id);
            if (existingElement.length > 0) {
                existingElement.data(element.data);
            } else {
                this.cy.add(element);
                if (element.group === 'nodes') {
                    wasNodeAdded = true;
                }
            }
        });

        if (wasNodeAdded) {
            // Use hierarchical layout for large networks
            const nodeCount = this.cy.nodes().length;
            const layoutName = nodeCount > 50 ? 'breadthfirst' : 'cose';
            
            this.cy.layout({
                name: layoutName,
                animate: true,
                animationDuration: nodeCount > 100 ? 500 : 1000,
                fit: true,
                padding: 30
            }).run();
        }

        this.updateNetworkStatsFromGraph();
    }

    updateNetworkStatistics(data) {
        // Update comprehensive network statistics from scan completion
        if (data.devices_found !== undefined) {
            this.elements.totalDevices.textContent = data.devices_found.toLocaleString();
        }
        
        if (data.online_devices !== undefined) {
            this.elements.onlineDevices.textContent = data.online_devices.toLocaleString();
        }
        
        if (data.total_open_ports !== undefined) {
            this.elements.openPorts.textContent = data.total_open_ports.toLocaleString();
        }
        
        if (data.coverage_percentage !== undefined) {
            this.elements.subnetCoverage.textContent = `${Math.round(data.coverage_percentage)}%`;
        }
        
        if (data.subnet_distribution) {
            this.elements.activeSubnets.textContent = Object.keys(data.subnet_distribution).length.toLocaleString();
        }
        
        if (data.duration) {
            const timeAgo = this.formatTimeAgo(new Date(Date.now() - (data.duration * 1000)));
            this.elements.scanTime.textContent = timeAgo;
        }
    }

    updateNetworkStatsFromGraph() {
        const nodes = this.cy.nodes();
        const totalDevices = nodes.length;
        const onlineDevices = nodes.filter(node => node.data('status') === 'up').length;
        let totalOpenPorts = 0;

        nodes.forEach(node => {
            const openPorts = node.data('open_ports') || [];
            totalOpenPorts += openPorts.length;
        });

        // Update statistics display
        this.elements.totalDevices.textContent = totalDevices.toLocaleString();
        this.elements.onlineDevices.textContent = onlineDevices.toLocaleString();
        this.elements.openPorts.textContent = totalOpenPorts.toLocaleString();

        // Update network statistics
        this.networkStats.totalDevices = totalDevices;
        this.networkStats.onlineDevices = onlineDevices;
        this.networkStats.openPorts = totalOpenPorts;
    }

    selectNode(node) {
        // Deselect previous node
        if (this.selectedNode) {
            this.selectedNode.removeClass('selected');
        }
        
        // Select new node
        this.selectedNode = node;
        node.addClass('selected');
        
        // Highlight connected edges
        const connectedEdges = node.connectedEdges();
        this.cy.edges().removeClass('highlighted');
        connectedEdges.addClass('highlighted');
        
        // Update device details panel
        this.updateDeviceDetails(node.data());
    }

    deselectNode() {
        if (this.selectedNode) {
            this.selectedNode.removeClass('selected');
            this.selectedNode = null;
        }
        
        this.cy.edges().removeClass('highlighted');
        this.clearDeviceDetails();
    }

    updateDeviceDetails(nodeData) {
        const deviceDetails = this.elements.deviceDetails;
        deviceDetails.classList.remove('empty');
        
        const deviceTypeMap = {
            'gateway': 'fas fa-network-wired',
            'router': 'fas fa-route',
            'web_server': 'fas fa-server',
            'linux_server': 'fab fa-linux',
            'windows_server': 'fab fa-windows',
            'printer': 'fas fa-print',
            'smart_device': 'fas fa-microchip',
            'iot_device': 'fas fa-wifi',
            'computer': 'fas fa-desktop',
            'unknown': 'fas fa-question-circle'
        };

        const deviceIcon = deviceTypeMap[nodeData.device_type] || deviceTypeMap['unknown'];
        const statusClass = nodeData.status === 'up' ? 'up' : 'down';
        
        deviceDetails.innerHTML = `
            <div class="device-card active">
                <div class="device-header">
                    <div class="device-icon">
                        <i class="${deviceIcon}"></i>
                    </div>
                    <div class="device-info">
                        <h3>${nodeData.id}</h3>
                        <span class="device-status ${statusClass}">
                            <i class="fas fa-circle"></i>
                            ${nodeData.status === 'up' ? 'Online' : 'Offline'}
                        </span>
                    </div>
                </div>
                
                <div class="device-details-content">
                    <div class="detail-row">
                        <span class="detail-label">Device Type</span>
                        <span class="detail-value">${this.formatDeviceType(nodeData.device_type)}</span>
                    </div>
                    
                    ${nodeData.mac ? `
                    <div class="detail-row">
                        <span class="detail-label">MAC Address</span>
                        <span class="detail-value">${nodeData.mac}</span>
                    </div>
                    ` : ''}
                    
                    ${nodeData.scan_duration ? `
                    <div class="detail-row">
                        <span class="detail-label">Scan Duration</span>
                        <span class="detail-value">${Math.round(nodeData.scan_duration * 1000)}ms</span>
                    </div>
                    ` : ''}
                    
                    ${nodeData.last_seen ? `
                    <div class="detail-row">
                        <span class="detail-label">Last Seen</span>
                        <span class="detail-value">${this.formatTimeAgo(new Date(nodeData.last_seen * 1000))}</span>
                    </div>
                    ` : ''}
                    
                    ${nodeData.subnet_info?.subnet_24 ? `
                    <div class="detail-row">
                        <span class="detail-label">Subnet</span>
                        <span class="detail-value">${nodeData.subnet_info.subnet_24}</span>
                    </div>
                    ` : ''}
                    
                    ${nodeData.open_ports && nodeData.open_ports.length > 0 ? `
                    <div class="detail-row">
                        <span class="detail-label">Open Ports</span>
                        <div class="ports-list">
                            ${nodeData.open_ports.map(port => 
                                `<span class="port-badge" title="${port.service || 'Unknown service'}">${port.port}/${port.protocol || 'tcp'}</span>`
                            ).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    clearDeviceDetails() {
        const deviceDetails = this.elements.deviceDetails;
        deviceDetails.classList.add('empty');
        deviceDetails.innerHTML = `
            <i class="fas fa-mouse-pointer" style="font-size: 3rem; color: var(--text-secondary); margin-bottom: 1rem;"></i>
            <p>Select a device from the network graph to view its information</p>
        `;
    }

    formatDeviceType(deviceType) {
        const typeMap = {
            'gateway': 'Gateway',
            'router': 'Router',
            'web_server': 'Web Server',
            'linux_server': 'Linux Server',
            'windows_server': 'Windows Server',
            'printer': 'Printer',
            'smart_device': 'Smart Device',
            'iot_device': 'IoT Device',
            'computer': 'Computer',
            'firewall_device': 'Firewall',
            'specialized_device': 'Specialized Device',
            'unknown': 'Unknown Device'
        };
        
        return typeMap[deviceType] || 'Unknown Device';
    }

    formatTimeAgo(date) {
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);
        
        if (diffInSeconds < 60) {
            return 'Just now';
        } else if (diffInSeconds < 3600) {
            const minutes = Math.floor(diffInSeconds / 60);
            return `${minutes}m ago`;
        } else if (diffInSeconds < 86400) {
            const hours = Math.floor(diffInSeconds / 3600);
            return `${hours}h ago`;
        } else {
            const days = Math.floor(diffInSeconds / 86400);
            return `${days}d ago`;
        }
    }

    toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(err => {
                console.log(`Error attempting to enable fullscreen: ${err.message}`);
            });
            this.elements.fullscreen.innerHTML = '<i class="fas fa-compress"></i>';
        } else {
            document.exitFullscreen();
            this.elements.fullscreen.innerHTML = '<i class="fas fa-expand"></i>';
        }
    }

    exportData() {
        try {
            const nodes = this.cy.nodes().map(node => node.data());
            const edges = this.cy.edges().map(edge => edge.data());
            
            const exportData = {
                timestamp: new Date().toISOString(),
                networkStats: this.networkStats,
                nodes: nodes,
                edges: edges,
                scanConfig: this.currentScanConfig
            };

            const dataStr = JSON.stringify(exportData, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            
            const link = document.createElement('a');
            link.href = URL.createObjectURL(dataBlob);
            link.download = `lanscope-export-${new Date().toISOString().split('T')[0]}.json`;
            link.click();
            
            this.showNotification('Network data exported successfully!', 'success');
        } catch (error) {
            console.error('Export failed:', error);
            this.showNotification('Failed to export data', 'error');
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            background: var(--${type === 'success' ? 'success' : type === 'error' ? 'danger' : 'primary'}-color);
            color: white;
            border-radius: 0.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            z-index: 9999;
            max-width: 300px;
            transform: translateX(100%);
            transition: transform 0.3s ease;
            font-size: 0.875rem;
            font-weight: 500;
        `;
        
        // Add icon based on type
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            info: 'fas fa-info-circle'
        };
        
        notification.innerHTML = `
            <i class="${icons[type] || icons.info}" style="margin-right: 0.5rem;"></i>
            ${message}
        `;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);
        
        // Auto remove
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 4000);
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing LanScope Advanced Application...');
    window.lanScopeApp = new LanScopeAdvancedApp();
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (window.lanScopeApp && window.lanScopeApp.socket) {
        if (document.hidden) {
            console.log('Page hidden, maintaining socket connection');
        } else {
            console.log('Page visible, ensuring socket connection');
            if (!window.lanScopeApp.socket.connected) {
                window.lanScopeApp.socket.connect();
            }
        }
    }
});

// Handle window resize
window.addEventListener('resize', () => {
    if (window.lanScopeApp && window.lanScopeApp.cy) {
        window.lanScopeApp.cy.resize();
        window.lanScopeApp.cy.center();
    }
});