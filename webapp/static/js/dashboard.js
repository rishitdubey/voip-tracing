// VoIP Tracing MVP Dashboard JavaScript

let currentTraceId = null;
let networkGraph = null;

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initializing...');
    loadDashboardData();
    
    // Auto-refresh every 30 seconds
    setInterval(refreshDashboard, 30000);
});

// Load initial dashboard data
function loadDashboardData() {
    updateTimestamp();
    loadStatistics();
    loadTraces();
}

// Refresh all dashboard data
function refreshDashboard() {
    console.log('Refreshing dashboard...');
    loadDashboardData();
    
    // Refresh current trace details if one is selected
    if (currentTraceId) {
        loadTraceDetails(currentTraceId);
    }
}

// Update the last updated timestamp
function updateTimestamp() {
    const now = new Date();
    document.getElementById('update-time').textContent = now.toLocaleTimeString();
}

// Load overall statistics
function loadStatistics() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Error loading stats:', data.error);
                return;
            }
            
            document.getElementById('total-traces').textContent = data.total_traces;
            document.getElementById('total-sessions').textContent = data.total_sessions;
            document.getElementById('total-flows').textContent = data.total_flows;
            document.getElementById('total-correlations').textContent = data.total_correlations;
            document.getElementById('total-security-events').textContent = data.total_security_events;
        })
        .catch(error => {
            console.error('Error loading statistics:', error);
        });
}

// Load traces list
function loadTraces() {
    fetch('/api/traces')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Error loading traces:', data.error);
                displayError('traces-table', 'Failed to load traces');
                return;
            }
            
            displayTracesTable(data.traces);
        })
        .catch(error => {
            console.error('Error loading traces:', error);
            displayError('traces-table', 'Network error loading traces');
        });
}

// Display traces in table
function displayTracesTable(traces) {
    const tbody = document.getElementById('traces-table');
    
    if (!traces || traces.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No traces found</td></tr>';
        return;
    }
    
    tbody.innerHTML = traces.map(trace => `
        <tr>
            <td>
                <code class="text-primary">${trace.trace_id}</code>
            </td>
            <td>
                <span class="badge bg-success">${trace.sip_sessions}</span>
            </td>
            <td>
                <span class="badge bg-info">${trace.rtp_flows}</span>
            </td>
            <td>
                <small class="text-muted">${formatDateTime(trace.first_seen)}</small>
            </td>
            <td>
                <small>${trace.duration}</small>
            </td>
            <td>
                <button class="btn btn-sm btn-primary me-1" onclick="viewTraceDetails('${trace.trace_id}')">
                    <i class="fas fa-eye"></i> View
                </button>
                <button class="btn btn-sm btn-warning me-1" onclick="analyzeTrace('${trace.trace_id}')">
                    <i class="fas fa-chart-line"></i> Analyze
                </button>
                <button class="btn btn-sm btn-danger" onclick="securityAnalyze('${trace.trace_id}')">
                    <i class="fas fa-shield-alt"></i> Security
                </button>
            </td>
        </tr>
    `).join('');
}

// View trace details
function viewTraceDetails(traceId) {
    currentTraceId = traceId;
    document.getElementById('traceDetailsModalLabel').textContent = `Trace Details: ${traceId}`;
    
    showModal('traceDetailsModal');
    loadTraceDetails(traceId);
}

// Load detailed trace information
function loadTraceDetails(traceId) {
    const content = document.getElementById('trace-details-content');
    content.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p>Loading trace details...</p></div>';
    
    fetch(`/api/trace/${traceId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                content.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
                return;
            }
            
            displayTraceDetails(data);
        })
        .catch(error => {
            console.error('Error loading trace details:', error);
            content.innerHTML = '<div class="alert alert-danger">Network error loading trace details</div>';
        });
}

// Display trace details
function displayTraceDetails(data) {
    const content = document.getElementById('trace-details-content');
    
    const html = `
        <div class="row">
            <div class="col-md-6">
                <h6><i class="fas fa-phone me-2"></i>SIP Sessions (${data.sessions.length})</h6>
                <div class="mb-3" style="max-height: 300px; overflow-y: auto;">
                    ${data.sessions.map(session => `
                        <div class="card bg-dark mb-2">
                            <div class="card-body py-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>${session.from_uri || 'Unknown'}</strong> → <strong>${session.to_uri || 'Unknown'}</strong>
                                    </div>
                                    <span class="badge ${getStatusBadgeClass(session.status)}">${session.status}</span>
                                </div>
                                <small class="text-muted">
                                    <i class="fas fa-clock me-1"></i>${formatDateTime(session.start_time)}
                                </small>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="col-md-6">
                <h6><i class="fas fa-stream me-2"></i>RTP Flows (${data.flows.length})</h6>
                <div class="mb-3" style="max-height: 300px; overflow-y: auto;">
                    ${data.flows.map(flow => `
                        <div class="card bg-dark mb-2">
                            <div class="card-body py-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>${flow.src_endpoint}</strong> → <strong>${flow.dst_endpoint}</strong>
                                    </div>
                                    <div>
                                        <span class="badge bg-info">${flow.packet_count} pkts</span>
                                        ${flow.payload_type ? `<span class="badge bg-secondary">PT${flow.payload_type}</span>` : ''}
                                    </div>
                                </div>
                                <small class="text-muted">SSRC: ${flow.ssrc}</small>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
        
        ${data.correlations.length > 0 ? `
        <div class="row mt-3">
            <div class="col-12">
                <h6><i class="fas fa-link me-2"></i>Correlations (${data.correlations.length})</h6>
                <div style="max-height: 200px; overflow-y: auto;">
                    ${data.correlations.map(corr => `
                        <div class="correlation-item">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <strong>${corr.from_uri || 'Unknown'}</strong> → <strong>${corr.to_uri || 'Unknown'}</strong>
                                    <br><small class="text-muted">SSRC: ${corr.ssrc}</small>
                                </div>
                                <div class="text-end">
                                    <div class="confidence-bar mb-1" style="width: 100px;">
                                        <div class="confidence-fill ${getConfidenceClass(corr.confidence)}" 
                                             style="width: ${(corr.confidence * 100)}%"></div>
                                    </div>
                                    <small>${(corr.confidence * 100).toFixed(1)}% confidence</small>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
        ` : ''}
    `;
    
    content.innerHTML = html;
}

// Analyze trace (correlation analysis)
function analyzeTrace(traceId) {
    currentTraceId = traceId;
    showLoadingModal('Running Correlation Analysis...');
    
    // Switch to analysis tab and load correlation data
    document.getElementById('analysis-tab').click();
    
    fetch(`/api/correlation/${traceId}`)
        .then(response => response.json())
        .then(data => {
            hideModal('loadingModal');
            
            if (data.error) {
                displayAnalysisError(data.error);
                return;
            }
            
            displayCorrelationAnalysis(data);
        })
        .catch(error => {
            hideModal('loadingModal');
            console.error('Error running correlation analysis:', error);
            displayAnalysisError('Network error during correlation analysis');
        });
}

// Display correlation analysis results
function displayCorrelationAnalysis(data) {
    const callFlowDetails = document.getElementById('call-flow-details');
    const correlationStatus = document.getElementById('correlation-status');
    
    // Display call flow report
    if (data.report && data.report.calls) {
        callFlowDetails.innerHTML = `
            <h6>Call Flow Report</h6>
            <div class="mb-3">
                <div class="row">
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-primary">${data.report.metadata.total_correlated_calls}</h4>
                            <small class="text-muted">Total Calls</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-success">${data.report.metadata.high_confidence_calls}</h4>
                            <small class="text-muted">High Confidence</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-warning">${data.report.metadata.medium_confidence_calls}</h4>
                            <small class="text-muted">Medium Confidence</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-info">${data.report.summary.average_confidence.toFixed(2)}</h4>
                            <small class="text-muted">Avg Confidence</small>
                        </div>
                    </div>
                </div>
            </div>
            
            <div style="max-height: 400px; overflow-y: auto;">
                ${data.report.calls.map(call => `
                    <div class="card bg-dark mb-2">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <strong>${call.from_uri || 'Unknown'}</strong> → <strong>${call.to_uri || 'Unknown'}</strong>
                                    <br><small class="text-muted">${formatDateTime(call.start_time)}</small>
                                </div>
                                <div class="text-end">
                                    <span class="badge ${getStatusBadgeClass(call.status)}">${call.status}</span>
                                    <br><small class="text-muted">${(call.confidence * 100).toFixed(1)}% confidence</small>
                                </div>
                            </div>
                            ${call.media_flows && call.media_flows.length > 0 ? `
                            <div class="mt-2">
                                <small class="text-muted">Media Flows:</small>
                                ${call.media_flows.map(flow => `
                                    <div class="d-flex justify-content-between mt-1">
                                        <small>${flow.src_endpoint} → ${flow.dst_endpoint}</small>
                                        <small>${flow.packet_count} packets</small>
                                    </div>
                                `).join('')}
                            </div>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } else {
        callFlowDetails.innerHTML = '<p class="text-muted">No correlation data available</p>';
    }
    
    // Display correlation status
    correlationStatus.innerHTML = `
        <div class="mb-2">
            <h6>Analysis Status</h6>
            <span class="badge bg-success">Complete</span>
        </div>
        <div class="mb-2">
            <small class="text-muted">Correlations Found:</small>
            <br><strong>${data.correlations ? data.correlations.length : 0}</strong>
        </div>
        <div class="mb-2">
            <small class="text-muted">Methods Used:</small>
            <br>${data.report && data.report.summary.correlation_methods ? 
                Object.keys(data.report.summary.correlation_methods).join(', ') : 
                'multi-method'}
        </div>
    `;
}

// Security analysis
function securityAnalyze(traceId) {
    currentTraceId = traceId;
    showLoadingModal('Running Security Analysis...');
    
    // Switch to security tab
    document.getElementById('security-tab').click();
    
    fetch(`/api/security/${traceId}`)
        .then(response => response.json())
        .then(data => {
            hideModal('loadingModal');
            
            if (data.error) {
                displaySecurityError(data.error);
                return;
            }
            
            displaySecurityAnalysis(data);
        })
        .catch(error => {
            hideModal('loadingModal');
            console.error('Error running security analysis:', error);
            displaySecurityError('Network error during security analysis');
        });
}

// Display security analysis results
function displaySecurityAnalysis(data) {
    const securityAnalysis = document.getElementById('security-analysis');
    
    const riskLevel = getRiskLevel(data.risk_score);
    
    securityAnalysis.innerHTML = `
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="text-center">
                    <h2 class="text-${riskLevel.color}">${data.risk_score.toFixed(1)}</h2>
                    <p class="mb-0">Risk Score</p>
                    <small class="text-muted">${riskLevel.text}</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="text-center">
                    <h3 class="text-danger">${data.summary.high_risk_events}</h3>
                    <small class="text-muted">High Risk Events</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="text-center">
                    <h3 class="text-warning">${data.summary.medium_risk_events}</h3>
                    <small class="text-muted">Medium Risk Events</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="text-center">
                    <h3 class="text-info">${data.summary.low_risk_events}</h3>
                    <small class="text-muted">Low Risk Events</small>
                </div>
            </div>
        </div>
        
        ${data.security_events && data.security_events.length > 0 ? `
        <div class="mb-4">
            <h6>Security Events</h6>
            <div style="max-height: 400px; overflow-y: auto;">
                ${data.security_events.map(event => `
                    <div class="security-event ${event.severity.toLowerCase()}">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="mb-1">
                                    <span class="badge bg-${getSeverityColor(event.severity)}">${event.severity}</span>
                                    ${event.type.replace(/_/g, ' ').toUpperCase()}
                                </h6>
                                <p class="mb-1">${event.description}</p>
                                ${event.src_ip ? `<small class="text-muted">Source: ${event.src_ip}</small>` : ''}
                                ${event.dst_ip ? `<small class="text-muted">Destination: ${event.dst_ip}</small>` : ''}
                            </div>
                            <small class="text-muted">${formatDateTime(event.timestamp)}</small>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : '<div class="alert alert-success">No security events detected</div>'}
        
        ${data.recommendations && data.recommendations.length > 0 ? `
        <div class="mb-4">
            <h6>Recommendations</h6>
            <ul class="list-group list-group-flush">
                ${data.recommendations.map(rec => `
                    <li class="list-group-item bg-transparent text-light border-secondary">
                        <i class="fas fa-lightbulb text-warning me-2"></i>${rec}
                    </li>
                `).join('')}
            </ul>
        </div>
        ` : ''}
    `;
}

// Network visualization
function showNetworkView(traceId) {
    currentTraceId = traceId;
    document.getElementById('network-tab').click();
    
    const networkGraph = document.getElementById('network-graph');
    networkGraph.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p>Loading network topology...</p></div>';
    
    fetch(`/api/network-graph/${traceId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                networkGraph.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
                return;
            }
            
            renderNetworkGraph(data);
        })
        .catch(error => {
            console.error('Error loading network graph:', error);
            networkGraph.innerHTML = '<div class="alert alert-danger">Network error loading topology</div>';
        });
}

// Render network graph using D3.js
function renderNetworkGraph(graphData) {
    const container = document.getElementById('network-graph');
    container.innerHTML = '';
    
    const width = container.clientWidth;
    const height = 600;
    
    const svg = d3.select('#network-graph')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Create force simulation
    const simulation = d3.forceSimulation(graphData.nodes)
        .force('link', d3.forceLink(graphData.edges).id(d => d.id).distance(150))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2));
    
    // Create links
    const link = svg.append('g')
        .selectAll('line')
        .data(graphData.edges)
        .enter().append('line')
        .attr('class', 'link')
        .style('stroke-width', d => Math.sqrt(d.count))
        .style('stroke', d => d.protocol === 'sip' ? '#28a745' : '#17a2b8');
    
    // Create nodes
    const node = svg.append('g')
        .selectAll('circle')
        .data(graphData.nodes)
        .enter().append('circle')
        .attr('class', 'node-circle')
        .attr('r', 20)
        .style('fill', d => d.protocols.includes('sip') ? '#28a745' : '#17a2b8')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // Add labels
    const label = svg.append('g')
        .selectAll('text')
        .data(graphData.nodes)
        .enter().append('text')
        .attr('class', 'node-label')
        .text(d => d.label)
        .attr('dy', 5);
    
    // Add tooltips
    node.append('title')
        .text(d => `${d.label}\nProtocols: ${d.protocols.join(', ')}`);
    
    link.append('title')
        .text(d => `${d.source.id} → ${d.target.id}\n${d.label}`);
    
    // Update positions on simulation tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        node
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
        
        label
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });
    
    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}

// Run correlation from modal
function runCorrelation() {
    if (currentTraceId) {
        hideModal('traceDetailsModal');
        analyzeTrace(currentTraceId);
    }
}

// Run security analysis from modal
function runSecurityAnalysis() {
    if (currentTraceId) {
        hideModal('traceDetailsModal');
        securityAnalyze(currentTraceId);
    }
}

// Utility functions
function formatDateTime(dateString) {
    if (!dateString) return 'Unknown';
    try {
        const date = new Date(dateString);
        return date.toLocaleString();
    } catch (e) {
        return dateString;
    }
}

function getStatusBadgeClass(status) {
    switch (status) {
        case 'CONNECTED': return 'bg-success';
        case 'CLIENT_ERROR': return 'bg-warning';
        case 'SERVER_ERROR': return 'bg-danger';
        default: return 'bg-secondary';
    }
}

function getConfidenceClass(confidence) {
    if (confidence >= 0.8) return 'confidence-high';
    if (confidence >= 0.5) return 'confidence-medium';
    return 'confidence-low';
}

function getSeverityColor(severity) {
    switch (severity.toUpperCase()) {
        case 'HIGH': case 'CRITICAL': return 'danger';
        case 'MEDIUM': return 'warning';
        case 'LOW': return 'info';
        default: return 'secondary';
    }
}

function getRiskLevel(score) {
    if (score >= 8) return { color: 'danger', text: 'CRITICAL RISK' };
    if (score >= 6) return { color: 'danger', text: 'HIGH RISK' };
    if (score >= 4) return { color: 'warning', text: 'MEDIUM RISK' };
    if (score >= 2) return { color: 'info', text: 'LOW RISK' };
    return { color: 'success', text: 'MINIMAL RISK' };
}

function showModal(modalId) {
    const modal = new bootstrap.Modal(document.getElementById(modalId));
    modal.show();
}

function hideModal(modalId) {
    const modal = bootstrap.Modal.getInstance(document.getElementById(modalId));
    if (modal) modal.hide();
}

function showLoadingModal(message) {
    document.getElementById('loading-message').textContent = message;
    showModal('loadingModal');
}

function displayError(elementId, message) {
    const element = document.getElementById(elementId);
    element.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Error: ${message}</td></tr>`;
}

function displayAnalysisError(message) {
    document.getElementById('call-flow-details').innerHTML = `<div class="alert alert-danger">Error: ${message}</div>`;
    document.getElementById('correlation-status').innerHTML = `<div class="alert alert-danger">Analysis failed</div>`;
}

function displaySecurityError(message) {
    document.getElementById('security-analysis').innerHTML = `<div class="alert alert-danger">Error: ${message}</div>`;
}

// Tab change handlers
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('network-tab').addEventListener('click', function() {
        if (currentTraceId) {
            setTimeout(() => showNetworkView(currentTraceId), 100);
        }
    });
});