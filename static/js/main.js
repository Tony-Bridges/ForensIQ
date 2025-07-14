
// ForensIQ Enterprise Digital Forensics Platform
// Main JavaScript functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize ForensIQ framework
    initializeForensIQ();
    
    // Initialize tooltips and popovers
    initializeBootstrapComponents();
    
    // Initialize real-time features
    initializeRealTimeFeatures();
    
    // Initialize file upload validation
    initializeFileUpload();
    
    // Initialize keyboard shortcuts
    initializeKeyboardShortcuts();
});

function initializeForensIQ() {
    // Extend the global forensiq object
    window.forensiq = {
        ...window.forensiq,
        version: '2.0.0',
        charts: new Map(),
        realtime: null,
        activeScans: new Set(),
        
        // Device scanning functionality
        scanDevices: async function() {
            try {
                this.showNotification('info', 'Scanning for connected devices...');
                
                const response = await fetch('/api/devices/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const result = await response.json();
                
                if (result.success) {
                    this.showNotification('success', 
                        `Device scan completed. Found ${result.devices.length} devices.`);
                    return result.devices;
                } else {
                    throw new Error(result.error || 'Scan failed');
                }
                
            } catch (error) {
                this.showNotification('error', `Device scan failed: ${error.message}`);
                throw error;
            }
        },
        
        // Start real-time monitoring
        startMonitoring: function(target) {
            if (this.activeScans.has(target)) {
                this.showNotification('warning', `Monitoring already active for ${target}`);
                return;
            }
            
            this.activeScans.add(target);
            this.showNotification('info', `Started monitoring ${target}`);
            
            // Start monitoring visualization
            this.updateMonitoringDisplay();
        },
        
        // Stop monitoring
        stopMonitoring: function(target) {
            if (this.activeScans.has(target)) {
                this.activeScans.delete(target);
                this.showNotification('info', `Stopped monitoring ${target}`);
                this.updateMonitoringDisplay();
            }
        },
        
        // Update monitoring display
        updateMonitoringDisplay: function() {
            const activeScanElements = document.querySelectorAll('.active-scan-indicator');
            activeScanElements.forEach(element => {
                element.textContent = this.activeScans.size;
            });
        },
        
        // Enhanced notification system
        showNotification: function(type, message, duration = 5000, persistent = false) {
            const container = document.getElementById('notification-container');
            if (!container) return;
            
            const notification = document.createElement('div');
            notification.className = `alert alert-${type} alert-dismissible fade show notification-slide-in`;
            notification.innerHTML = `
                <i class="fas fa-${this.getNotificationIcon(type)} me-2"></i>
                <strong>${this.getNotificationTitle(type)}:</strong> ${message}
                ${!persistent ? '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>' : ''}
            `;
            
            container.appendChild(notification);
            
            if (!persistent) {
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.classList.remove('show');
                        setTimeout(() => notification.remove(), 300);
                    }
                }, duration);
            }
            
            return notification;
        },
        
        getNotificationIcon: function(type) {
            const icons = {
                'success': 'check-circle',
                'error': 'exclamation-circle',
                'warning': 'exclamation-triangle',
                'info': 'info-circle',
                'danger': 'exclamation-circle'
            };
            return icons[type] || 'info-circle';
        },
        
        getNotificationTitle: function(type) {
            const titles = {
                'success': 'Success',
                'error': 'Error',
                'warning': 'Warning',
                'info': 'Information',
                'danger': 'Alert'
            };
            return titles[type] || 'Notification';
        },
        
        // Chart creation utilities
        createChart: function(canvasId, config) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return null;
            
            const ctx = canvas.getContext('2d');
            const chart = new Chart(ctx, {
                ...config,
                options: {
                    ...config.options,
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        ...config.options?.plugins,
                        legend: {
                            labels: {
                                color: '#a0a9b8'
                            }
                        }
                    },
                    scales: {
                        ...config.options?.scales,
                        x: {
                            ...config.options?.scales?.x,
                            ticks: { color: '#a0a9b8' },
                            grid: { color: 'rgba(160, 169, 184, 0.1)' }
                        },
                        y: {
                            ...config.options?.scales?.y,
                            ticks: { color: '#a0a9b8' },
                            grid: { color: 'rgba(160, 169, 184, 0.1)' }
                        }
                    }
                }
            });
            
            this.charts.set(canvasId, chart);
            return chart;
        },
        
        // Update chart data
        updateChart: function(chartId, newData) {
            const chart = this.charts.get(chartId);
            if (chart) {
                chart.data = newData;
                chart.update('none');
            }
        }
    };
    
    console.log('ForensIQ Framework initialized');
}

function initializeBootstrapComponents() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Initialize tabs with enhanced functionality
    const tabElements = document.querySelectorAll('[data-bs-toggle="tab"]');
    tabElements.forEach(tab => {
        new bootstrap.Tab(tab);
        
        // Add tab activation tracking
        tab.addEventListener('shown.bs.tab', function(e) {
            const targetId = e.target.getAttribute('data-bs-target');
            console.log(`Tab activated: ${targetId}`);
            
            // Trigger chart resize if needed
            if (window.forensiq) {
                window.forensiq.charts.forEach(chart => {
                    chart.resize();
                });
            }
        });
    });
}

function initializeRealTimeFeatures() {
    // Simulate real-time updates for demo purposes
    // In production, this would connect to WebSocket or Server-Sent Events
    
    setInterval(() => {
        // Update system metrics
        updateSystemMetrics();
        
        // Simulate occasional events
        if (Math.random() < 0.1) {
            simulateForensicsEvent();
        }
    }, 10000);
    
    // Initialize connection status monitoring
    monitorConnectionStatus();
}

function updateSystemMetrics() {
    // Update various system metrics with realistic values
    const metrics = {
        cpu: Math.round(20 + Math.random() * 30),
        memory: Math.round(50 + Math.random() * 30),
        disk: Math.round(30 + Math.random() * 20),
        network: Math.round(Math.random() * 100)
    };
    
    // Update metric displays
    updateMetricDisplay('cpu-usage', metrics.cpu, '%');
    updateMetricDisplay('memory-usage', metrics.memory, '%');
    updateMetricDisplay('disk-usage', metrics.disk, '%');
    
    // Update progress bars
    updateProgressBar('cpu-usage', metrics.cpu);
    updateProgressBar('memory-usage', metrics.memory);
    updateProgressBar('disk-usage', metrics.disk);
}

function updateMetricDisplay(metricId, value, suffix = '') {
    const elements = document.querySelectorAll(`#${metricId}, [data-metric="${metricId}"]`);
    elements.forEach(element => {
        if (element) {
            const valueElement = element.querySelector('.metric-value') || element;
            if (valueElement) {
                valueElement.textContent = value + suffix;
            }
        }
    });
}

function updateProgressBar(metricId, value) {
    const elements = document.querySelectorAll(`#${metricId}`);
    elements.forEach(element => {
        const progressBar = element.querySelector('.forensics-progress-bar');
        if (progressBar) {
            progressBar.style.width = Math.min(value, 100) + '%';
            
            // Add color coding
            if (value > 80) {
                progressBar.style.background = 'var(--danger-color)';
            } else if (value > 60) {
                progressBar.style.background = 'var(--warning-color)';
            } else {
                progressBar.style.background = 'var(--gradient-primary)';
            }
        }
    });
}

function simulateForensicsEvent() {
    if (!window.forensiq) return;
    
    const events = [
        { type: 'success', message: 'Evidence uploaded successfully' },
        { type: 'info', message: 'New device detected on network' },
        { type: 'warning', message: 'Suspicious network activity detected' },
        { type: 'info', message: 'AI analysis completed' }
    ];
    
    const event = events[Math.floor(Math.random() * events.length)];
    window.forensiq.showNotification(event.type, event.message);
}

function monitorConnectionStatus() {
    const statusIndicator = document.querySelector('.system-status .status-indicator');
    
    // Simulate connection monitoring
    setInterval(() => {
        if (navigator.onLine) {
            if (statusIndicator) {
                statusIndicator.className = 'status-indicator status-online';
            }
            updateStatusText('System Online');
        } else {
            if (statusIndicator) {
                statusIndicator.className = 'status-indicator status-offline';
            }
            updateStatusText('System Offline');
        }
    }, 5000);
}

function updateStatusText(text) {
    const statusElements = document.querySelectorAll('.system-status span:not(.status-indicator)');
    statusElements.forEach(element => {
        if (element && !element.classList.contains('status-indicator')) {
            element.textContent = text;
        }
    });
}

function initializeFileUpload() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (!file) return;
            
            // File size validation (16MB limit)
            const maxSize = 16 * 1024 * 1024;
            if (file.size > maxSize) {
                if (window.forensiq) {
                    window.forensiq.showNotification('error', 
                        `File size exceeds 16MB limit. Selected file: ${(file.size / 1024 / 1024).toFixed(2)}MB`);
                }
                e.target.value = '';
                return;
            }
            
            // File type validation for certain inputs
            const allowedTypes = e.target.getAttribute('data-allowed-types');
            if (allowedTypes) {
                const types = allowedTypes.split(',');
                const isAllowed = types.some(type => 
                    file.type.includes(type) || file.name.toLowerCase().endsWith(type)
                );
                
                if (!isAllowed) {
                    if (window.forensiq) {
                        window.forensiq.showNotification('error', 
                            `File type not allowed. Allowed types: ${allowedTypes}`);
                    }
                    e.target.value = '';
                    return;
                }
            }
            
            // Show file selected notification
            if (window.forensiq) {
                window.forensiq.showNotification('info', 
                    `File selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)}MB)`);
            }
            
            // Update file input display
            updateFileInputDisplay(input, file);
        });
        
        // Drag and drop support
        const container = input.closest('.file-upload-container');
        if (container) {
            setupDragAndDrop(container, input);
        }
    });
}

function updateFileInputDisplay(input, file) {
    const container = input.closest('.file-upload-container');
    if (container) {
        const label = container.querySelector('.file-upload-label');
        if (label) {
            label.innerHTML = `
                <i class="fas fa-file me-2"></i>
                ${file.name}
                <small class="text-secondary d-block">${(file.size / 1024 / 1024).toFixed(2)}MB</small>
            `;
        }
    }
}

function setupDragAndDrop(container, input) {
    container.addEventListener('dragover', function(e) {
        e.preventDefault();
        container.classList.add('drag-over');
    });
    
    container.addEventListener('dragleave', function(e) {
        e.preventDefault();
        container.classList.remove('drag-over');
    });
    
    container.addEventListener('drop', function(e) {
        e.preventDefault();
        container.classList.remove('drag-over');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            input.files = files;
            input.dispatchEvent(new Event('change'));
        }
    });
}

function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + Shift + combinations
        if ((e.ctrlKey || e.metaKey) && e.shiftKey) {
            switch(e.key) {
                case 'S':
                    e.preventDefault();
                    if (window.forensiq) {
                        window.forensiq.scanDevices();
                    }
                    break;
                case 'A':
                    e.preventDefault();
                    window.location.href = '/ai_analysis';
                    break;
                case 'D':
                    e.preventDefault();
                    window.location.href = '/';
                    break;
                case 'U':
                    e.preventDefault();
                    window.location.href = '/analyze';
                    break;
            }
        }
        
        // Escape key to close notifications
        if (e.key === 'Escape') {
            const notifications = document.querySelectorAll('.alert');
            notifications.forEach(notification => {
                const closeButton = notification.querySelector('.btn-close');
                if (closeButton) {
                    closeButton.click();
                }
            });
        }
    });
    
    // Show keyboard shortcuts help
    if (window.forensiq) {
        window.forensiq.showKeyboardShortcuts = function() {
            const shortcuts = `
                <div class="keyboard-shortcuts">
                    <h5>Keyboard Shortcuts</h5>
                    <ul class="list-unstyled">
                        <li><kbd>Ctrl+Shift+S</kbd> - Start Device Scan</li>
                        <li><kbd>Ctrl+Shift+A</kbd> - AI Analysis</li>
                        <li><kbd>Ctrl+Shift+D</kbd> - Dashboard</li>
                        <li><kbd>Ctrl+Shift+U</kbd> - Upload Evidence</li>
                        <li><kbd>Esc</kbd> - Close Notifications</li>
                    </ul>
                </div>
            `;
            this.showNotification('info', shortcuts, 10000);
        };
    }
}

// Utility functions
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Export functions for external use
window.forensiqUtils = {
    formatBytes,
    formatTimestamp,
    generateUUID,
    updateMetricDisplay,
    updateProgressBar
};

console.log('ForensIQ main.js loaded successfully');
