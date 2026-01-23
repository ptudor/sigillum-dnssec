(function() {
    'use strict';

    // DOM elements
    const form = document.getElementById('validate-form');
    const domainInput = document.getElementById('domain-input');
    const modeSelect = document.getElementById('mode-select');
    const validateBtn = document.getElementById('validate-btn');
    const statusEl = document.getElementById('status');
    const resultsEl = document.getElementById('results');
    const queryNameEl = document.getElementById('query-name');
    const resultBadgesEl = document.getElementById('result-badges');
    const chainVisualizationEl = document.getElementById('chain-visualization');
    const durationValueEl = document.getElementById('duration-value');
    const zonesCountEl = document.getElementById('zones-count');
    const zoneTabsEl = document.getElementById('zone-tabs');
    const zoneContentEl = document.getElementById('zone-content');
    const rawJsonEl = document.getElementById('raw-json');

    // State
    let currentResult = null;
    let selectedZone = null;
    let eventSource = null;

    // Initialize
    function init() {
        form.addEventListener('submit', handleSubmit);

        // Check for domain in URL
        const params = new URLSearchParams(window.location.search);
        const domain = params.get('domain');
        if (domain) {
            domainInput.value = domain;
            startValidation(domain, modeSelect.value);
        }
    }

    // Handle form submission
    function handleSubmit(e) {
        e.preventDefault();
        const domain = domainInput.value.trim();
        if (!domain) return;

        // Update URL
        const url = new URL(window.location);
        url.searchParams.set('domain', domain);
        history.pushState({}, '', url);

        startValidation(domain, modeSelect.value);
    }

    // Start validation via SSE
    function startValidation(domain, mode) {
        // Cancel any existing connection
        if (eventSource) {
            eventSource.close();
        }

        // Reset UI
        resetResults();
        showStatus('loading', 'Validating ' + domain + '...');
        validateBtn.disabled = true;

        // Connect to SSE endpoint
        const url = '/validate?domain=' + encodeURIComponent(domain) + '&mode=' + encodeURIComponent(mode);
        eventSource = new EventSource(url);

        eventSource.addEventListener('start', function(e) {
            const data = JSON.parse(e.data);
            queryNameEl.textContent = data.domain;
            resultsEl.classList.remove('hidden');
        });

        eventSource.addEventListener('zone', function(e) {
            const data = JSON.parse(e.data);
            addZoneCard(data.zone, data.status, data.zone_result);
        });

        eventSource.addEventListener('progress', function(e) {
            const data = JSON.parse(e.data);
            showStatus('loading', 'Validating ' + data.zone + ' (' + data.action + ')...');
        });

        eventSource.addEventListener('warning', function(e) {
            const data = JSON.parse(e.data);
            console.warn('Warning:', data.message);
        });

        eventSource.addEventListener('cname', function(e) {
            const data = JSON.parse(e.data);
            addCNAMEIndicator(data.source, data.target);
        });

        eventSource.addEventListener('error', function(e) {
            if (e.data) {
                const data = JSON.parse(e.data);
                if (data.fatal) {
                    showStatus('error', data.message);
                    eventSource.close();
                    validateBtn.disabled = false;
                }
            } else {
                // Connection error
                showStatus('error', 'Connection lost');
                validateBtn.disabled = false;
            }
        });

        eventSource.addEventListener('complete', function(e) {
            const data = JSON.parse(e.data);
            completeValidation(data);
            eventSource.close();
            validateBtn.disabled = false;
        });

        eventSource.onerror = function() {
            if (eventSource.readyState === EventSource.CLOSED) {
                validateBtn.disabled = false;
            }
        };
    }

    // Reset results UI
    function resetResults() {
        currentResult = null;
        selectedZone = null;
        chainVisualizationEl.innerHTML = '';
        zoneTabsEl.innerHTML = '';
        zoneContentEl.innerHTML = '';
        resultBadgesEl.innerHTML = '';
        rawJsonEl.textContent = '';
        durationValueEl.textContent = '-';
        zonesCountEl.textContent = '-';
        resultsEl.classList.add('hidden');
        hideStatus();
    }

    // Show status message
    function showStatus(type, message) {
        statusEl.className = 'status ' + type;
        statusEl.textContent = message;
    }

    // Hide status message
    function hideStatus() {
        statusEl.className = 'status';
        statusEl.textContent = '';
    }

    // Add zone card to visualization
    function addZoneCard(zone, status, zoneResult) {
        // Add arrow if not first
        if (chainVisualizationEl.children.length > 0) {
            const arrow = document.createElement('span');
            arrow.className = 'chain-arrow';
            arrow.textContent = '\u2192';
            arrow.setAttribute('aria-hidden', 'true');
            chainVisualizationEl.appendChild(arrow);
        }

        // Create card
        const card = document.createElement('div');
        card.className = 'zone-card ' + status;
        card.setAttribute('role', 'button');
        card.setAttribute('tabindex', '0');
        card.setAttribute('aria-label', 'Zone ' + zone + ' status ' + status);
        card.dataset.zone = zone;

        // Zone name (display friendly)
        const displayName = zone === '.' ? 'root' : zone.replace(/\.$/, '');
        card.innerHTML = `
            <span class="zone-name">${escapeHtml(displayName)}</span>
            <span class="zone-status">${getStatusIcon(status)}</span>
            ${zoneResult && zoneResult.query_time_ns ? `<span class="zone-rtt">${formatRTT(zoneResult.query_time_ns)}</span>` : ''}
        `;

        // Store zone result
        if (zoneResult) {
            card.dataset.result = JSON.stringify(zoneResult);
        }

        // Click handler
        card.addEventListener('click', function() {
            selectZone(zone, zoneResult);
        });
        card.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                selectZone(zone, zoneResult);
            }
        });

        chainVisualizationEl.appendChild(card);

        // Add tab
        const tab = document.createElement('button');
        tab.className = 'zone-tab';
        tab.setAttribute('role', 'tab');
        tab.textContent = displayName;
        tab.dataset.zone = zone;
        tab.addEventListener('click', function() {
            selectZone(zone, zoneResult);
        });
        zoneTabsEl.appendChild(tab);

        // Auto-select first zone
        if (!selectedZone) {
            selectZone(zone, zoneResult);
        }
    }

    // Select a zone to show details
    function selectZone(zone, zoneResult) {
        selectedZone = zone;

        // Update card selection
        document.querySelectorAll('.zone-card').forEach(function(card) {
            card.classList.toggle('selected', card.dataset.zone === zone);
        });

        // Update tab selection
        document.querySelectorAll('.zone-tab').forEach(function(tab) {
            tab.classList.toggle('active', tab.dataset.zone === zone);
        });

        // Show zone details
        if (zoneResult) {
            showZoneDetails(zoneResult);
        }
    }

    // Show zone details
    function showZoneDetails(zoneResult) {
        let html = '';

        // Status
        html += '<div class="zone-status-header">';
        html += '<span class="badge ' + zoneResult.status + '">' + zoneResult.status + '</span>';
        html += '</div>';

        // Nameservers
        if (zoneResult.nameservers && zoneResult.nameservers.length > 0) {
            html += '<h4>Nameservers</h4>';
            html += '<ul class="ns-list">';
            zoneResult.nameservers.forEach(function(ns) {
                if (ns.addresses && ns.addresses.length > 0) {
                    ns.addresses.forEach(function(addr) {
                        html += '<li class="ns-item">';
                        html += '<span class="ns-status ' + getStatusClass(addr.status) + '">' + getStatusIcon(addr.status) + '</span>';
                        html += '<span class="ns-name">' + escapeHtml(ns.name) + '</span>';
                        html += '<span class="ns-ip">(' + escapeHtml(addr.ip) + ')</span>';
                        if (addr.rtt_ns) {
                            html += '<span class="ns-rtt">' + formatRTT(addr.rtt_ns) + '</span>';
                        }
                        html += '</li>';
                    });
                } else {
                    html += '<li class="ns-item">';
                    html += '<span class="ns-name">' + escapeHtml(ns.name) + '</span>';
                    html += '</li>';
                }
            });
            html += '</ul>';
        }

        // DNSKEY records
        if (zoneResult.dnskey && zoneResult.dnskey.length > 0) {
            html += '<h4>DNSKEY Records</h4>';
            zoneResult.dnskey.forEach(function(key) {
                html += '<div class="record-card">';
                html += '<div class="record-header">';
                html += '<span class="record-type">' + (key.is_ksk ? 'KSK' : 'ZSK') + '</span>';
                html += '<span class="record-tag">Tag: ' + key.key_tag + '</span>';
                html += '</div>';
                html += '<div class="record-data">' + escapeHtml(key.public_key.substring(0, 50)) + '...</div>';
                html += '<div class="record-meta">Algorithm: ' + key.algorithm + ' | Flags: ' + key.flags + '</div>';
                html += '</div>';
            });
        }

        // DS records
        if (zoneResult.ds && zoneResult.ds.length > 0) {
            html += '<h4>DS Records (from parent)</h4>';
            zoneResult.ds.forEach(function(ds) {
                html += '<div class="record-card">';
                html += '<div class="record-header">';
                html += '<span class="record-type">DS</span>';
                html += '<span class="record-tag">Tag: ' + ds.key_tag + '</span>';
                html += '</div>';
                html += '<div class="record-data">' + escapeHtml(ds.digest.substring(0, 50)) + '...</div>';
                html += '<div class="record-meta">Algorithm: ' + ds.algorithm + ' | Digest Type: ' + ds.digest_type + '</div>';
                html += '</div>';
            });
        }

        // Chain link
        if (zoneResult.chain_link) {
            html += '<h4>Chain of Trust</h4>';
            html += '<div class="record-card">';
            html += '<div class="record-data">';
            html += zoneResult.chain_link.ds_matches_ksk ?
                '<span class="ns-status secure">\u2713</span> DS matches DNSKEY' :
                '<span class="ns-status error">\u2717</span> DS does not match DNSKEY';
            html += '</div>';
            html += '<div class="record-meta">';
            html += 'Key Tag: ' + zoneResult.chain_link.key_tag;
            html += ' | Algorithm: ' + escapeHtml(zoneResult.chain_link.algorithm || 'N/A');
            html += '</div>';
            html += '</div>';
        }

        // Errors
        if (zoneResult.errors && zoneResult.errors.length > 0) {
            html += '<h4>Errors</h4>';
            zoneResult.errors.forEach(function(err) {
                html += '<div class="record-card" style="border-left: 3px solid var(--error);">';
                html += '<div class="record-data" style="color: var(--error);">' + escapeHtml(err) + '</div>';
                html += '</div>';
            });
        }

        // Warnings
        if (zoneResult.warnings && zoneResult.warnings.length > 0) {
            html += '<h4>Warnings</h4>';
            zoneResult.warnings.forEach(function(warn) {
                html += '<div class="record-card" style="border-left: 3px solid var(--warning);">';
                html += '<div class="record-data" style="color: var(--warning);">' + escapeHtml(warn) + '</div>';
                html += '</div>';
            });
        }

        zoneContentEl.innerHTML = html;
    }

    // Complete validation
    function completeValidation(data) {
        currentResult = data;
        hideStatus();

        // Update badges
        var badgeHtml = '<span class="badge ' + data.result + '">' + data.result + '</span>';

        // Add CNAME chain indicator if present
        if (data.cname_chains && data.cname_chains.length > 0) {
            data.cname_chains.forEach(function(chain) {
                badgeHtml += '<span class="badge ' + chain.result + '">CNAME: ' + chain.result + '</span>';
            });
        }
        resultBadgesEl.innerHTML = badgeHtml;

        // Update timing
        durationValueEl.textContent = data.duration_ms + 'ms';

        // Count zones including CNAME chains
        var zoneCount = data.chain ? data.chain.length : 0;
        if (data.cname_chains) {
            data.cname_chains.forEach(function(chain) {
                if (chain.chain) {
                    zoneCount += chain.chain.length;
                }
            });
        }
        zonesCountEl.textContent = zoneCount;

        // Add CNAME chain zones to visualization and tabs
        if (data.cname_chains && data.cname_chains.length > 0) {
            data.cname_chains.forEach(function(cnameChain) {
                if (cnameChain.chain) {
                    cnameChain.chain.forEach(function(zoneResult) {
                        addZoneCard(zoneResult.zone, zoneResult.status, zoneResult);
                    });
                }
            });
        }

        // Update raw JSON
        rawJsonEl.textContent = JSON.stringify(data, null, 2);
    }

    // Helper functions
    function getStatusIcon(status) {
        switch (status) {
            case 'secure': return '\u2713';
            case 'insecure': return '\u26A0';
            case 'bogus': return '\u2717';
            case 'indeterminate': return '?';
            case 'validating': return '\u2022';
            default: return '\u2022';
        }
    }

    function getStatusClass(status) {
        switch (status) {
            case 'secure': return 'secure';
            case 'insecure': return 'warning';
            case 'bogus': return 'error';
            case 'indeterminate': return 'warning';
            default: return '';
        }
    }

    function formatRTT(ns) {
        if (!ns) return '';
        const ms = ns / 1000000;
        if (ms < 1) {
            return (ns / 1000).toFixed(0) + '\u03bcs';
        }
        return ms.toFixed(0) + 'ms';
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Add CNAME indicator to chain visualization
    function addCNAMEIndicator(source, target) {
        // Add arrow indicating CNAME
        const arrow = document.createElement('span');
        arrow.className = 'chain-arrow cname-arrow';
        arrow.textContent = '\u2192 CNAME \u2192';
        arrow.setAttribute('aria-label', 'CNAME redirect');
        chainVisualizationEl.appendChild(arrow);

        // Add card for CNAME target
        const card = document.createElement('div');
        card.className = 'zone-card cname-target';
        card.setAttribute('role', 'button');
        card.setAttribute('tabindex', '0');
        card.setAttribute('aria-label', 'CNAME target ' + target);
        card.dataset.zone = target;

        const displayName = target.replace(/\.$/, '');
        card.innerHTML = '<span class="zone-name">' + escapeHtml(displayName) + '</span>' +
            '<span class="zone-status">CNAME</span>';

        chainVisualizationEl.appendChild(card);
    }

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
