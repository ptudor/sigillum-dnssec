(function() {
    'use strict';

    // DOM elements
    const form = document.getElementById('validate-form');
    const domainInput = document.getElementById('domain-input');
    const modeSelect = document.getElementById('mode-select');
    const validateBtn = document.getElementById('validate-btn');
    const statusEl = document.getElementById('status');
    const statusTextEl = statusEl.querySelector('.status-text');
    const resultsEl = document.getElementById('results');
    const queryNameEl = document.getElementById('query-name');
    const resultBadgesEl = document.getElementById('result-badges');
    const chainVisualizationEl = document.getElementById('chain-visualization');
    const durationValueEl = document.getElementById('duration-value');
    const zonesCountEl = document.getElementById('zones-count');
    const zoneTabsEl = document.getElementById('zone-tabs');
    const zoneContentEl = document.getElementById('zone-content');
    const rawJsonEl = document.getElementById('raw-json');
    const copyLinkBtn = document.getElementById('copy-link-btn');

    // State
    let currentResult = null;
    let selectedZone = null;
    let eventSource = null;
    let currentDepth = 0;
    let seenZones = new Set();
    let inCnameChain = false;

    // Initialize
    function init() {
        form.addEventListener('submit', handleSubmit);

        // Example domain buttons
        document.querySelectorAll('.example-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var domain = this.getAttribute('data-domain');
                domainInput.value = domain;
                startValidation(domain, modeSelect.value);
                updateURL(domain);
            });
        });

        // Copy link button
        if (copyLinkBtn) {
            copyLinkBtn.addEventListener('click', copyLink);
        }

        // Check for domain in URL
        const params = new URLSearchParams(window.location.search);
        const domain = params.get('domain');
        if (domain) {
            domainInput.value = domain;
            startValidation(domain, modeSelect.value);
        }
    }

    // Copy current URL to clipboard
    function copyLink() {
        navigator.clipboard.writeText(window.location.href).then(function() {
            copyLinkBtn.classList.add('copied');
            setTimeout(function() {
                copyLinkBtn.classList.remove('copied');
            }, 1500);
        }).catch(function(err) {
            console.error('Failed to copy:', err);
        });
    }

    // Update URL without reloading
    function updateURL(domain) {
        const url = new URL(window.location);
        url.searchParams.set('domain', domain);
        history.pushState({}, '', url);
    }

    // Handle form submission
    function handleSubmit(e) {
        e.preventDefault();
        const domain = domainInput.value.trim();
        if (!domain) return;

        updateURL(domain);
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

        // Connect to SSE endpoint (relative URL for path prefix support)
        const sseUrl = 'validate?domain=' + encodeURIComponent(domain) + '&mode=' + encodeURIComponent(mode);
        eventSource = new EventSource(sseUrl);

        eventSource.addEventListener('start', function(e) {
            const data = safeJSONParse(e.data);
            if (!data) return;
            queryNameEl.textContent = data.domain;
            resultsEl.classList.remove('hidden');
        });

        eventSource.addEventListener('zone', function(e) {
            const data = safeJSONParse(e.data);
            if (!data) return;
            addZoneCard(data.zone, data.status, data.zone_result);
        });

        eventSource.addEventListener('progress', function(e) {
            const data = safeJSONParse(e.data);
            if (!data) return;
            showStatus('loading', 'Validating ' + data.zone + ' (' + data.action + ')...');
        });

        eventSource.addEventListener('warning', function(e) {
            const data = safeJSONParse(e.data);
            if (!data) return;
            console.warn('Warning:', data.message);
        });

        eventSource.addEventListener('cname', function(e) {
            const data = safeJSONParse(e.data);
            if (!data) return;
            addCNAMEIndicator(data.source, data.target);
        });

        eventSource.addEventListener('error', function(e) {
            if (e.data) {
                const data = safeJSONParse(e.data);
                if (data && data.fatal) {
                    showStatus('error', data.message || 'Validation error');
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
            const data = safeJSONParse(e.data);
            if (!data) {
                showStatus('error', 'Invalid response from server');
                validateBtn.disabled = false;
                return;
            }
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
        currentDepth = 0;
        seenZones = new Set();
        inCnameChain = false;
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
        if (statusTextEl) {
            statusTextEl.textContent = message;
        } else {
            statusEl.textContent = message;
        }
    }

    // Hide status message
    function hideStatus() {
        statusEl.className = 'status';
        if (statusTextEl) {
            statusTextEl.textContent = '';
        } else {
            statusEl.textContent = '';
        }
    }

    // Build tree indent string
    function getIndent(depth) {
        if (depth === 0) return '';
        var indent = '';
        for (var i = 0; i < depth - 1; i++) {
            indent += '    ';
        }
        indent += '\u2514\u2500\u2500 '; // └──
        return indent;
    }

    // Add zone item to tree visualization
    function addZoneCard(zone, status, zoneResult) {
        var isCached = seenZones.has(zone);
        seenZones.add(zone);

        // Create tree item
        var item = document.createElement('div');
        item.className = 'zone-item ' + status + (isCached ? ' cached' : '');
        item.setAttribute('role', 'button');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-label', 'Zone ' + zone + ' status ' + status + (isCached ? ' (cached)' : ''));
        item.dataset.zone = zone;

        // Zone name (display friendly)
        var displayName = zone === '.' ? '.' : zone;

        // Build item HTML
        var html = '<span class="zone-indent" aria-hidden="true">' + getIndent(currentDepth) + '</span>';
        html += '<span class="zone-status-icon ' + status + '">' + getStatusIcon(status) + '</span>';
        html += '<span class="zone-name">' + escapeHtml(displayName) + '</span>';
        if (isCached) {
            html += '<span class="zone-cached-label">(cached)</span>';
        }
        if (zoneResult && zoneResult.query_time_ns && !isCached) {
            html += '<span class="zone-rtt">' + formatRTT(zoneResult.query_time_ns) + '</span>';
        }
        item.innerHTML = html;

        // Store zone result
        if (zoneResult) {
            item.dataset.result = JSON.stringify(zoneResult);
        }

        // Click handler
        item.addEventListener('click', function() {
            selectZone(zone, zoneResult);
        });
        item.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                selectZone(zone, zoneResult);
            }
        });

        chainVisualizationEl.appendChild(item);

        // Add tab (skip cached zones to avoid duplicates)
        if (!isCached) {
            var tab = document.createElement('button');
            tab.className = 'zone-tab';
            tab.setAttribute('role', 'tab');
            tab.textContent = zone === '.' ? 'root' : zone.replace(/\.$/, '');
            tab.dataset.zone = zone;
            tab.addEventListener('click', function() {
                selectZone(zone, zoneResult);
            });
            zoneTabsEl.appendChild(tab);
        }

        // Auto-select first zone
        if (!selectedZone) {
            selectZone(zone, zoneResult);
        }

        // Increment depth for next zone
        currentDepth++;
    }

    // Select a zone to show details
    function selectZone(zone, zoneResult) {
        selectedZone = zone;

        // Update tree item selection (only select first match to handle cached duplicates)
        var foundFirst = false;
        document.querySelectorAll('.zone-item').forEach(function(item) {
            if (item.dataset.zone === zone && !foundFirst) {
                item.classList.add('selected');
                foundFirst = true;
            } else if (item.dataset.zone === zone) {
                // Don't select duplicate cached entries
                item.classList.remove('selected');
            } else {
                item.classList.remove('selected');
            }
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

        // RRSIG records
        if (zoneResult.rrsig && zoneResult.rrsig.length > 0) {
            html += '<h4>RRSIG Records</h4>';
            zoneResult.rrsig.forEach(function(rrsig) {
                var validityClass = rrsig.is_valid ? 'secure' : (rrsig.is_expired ? 'error' : 'warning');
                var validityText = rrsig.is_valid ? 'Valid' : (rrsig.is_expired ? 'Expired' : 'Not yet valid');
                html += '<div class="record-card">';
                html += '<div class="record-header">';
                html += '<span class="record-type">RRSIG (' + getTypeName(rrsig.type_covered) + ')</span>';
                html += '<span class="record-tag ns-status ' + validityClass + '">' + validityText + '</span>';
                html += '</div>';
                html += '<div class="record-data">';
                html += 'Signer: ' + escapeHtml(rrsig.signer_name) + '<br>';
                html += 'Key Tag: ' + rrsig.key_tag;
                html += '</div>';
                html += '<div class="record-meta">';
                html += 'Valid: ' + formatDate(rrsig.inception) + ' to ' + formatDate(rrsig.expiration);
                html += ' | Algorithm: ' + rrsig.algorithm;
                html += '</div>';
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

    // Safe JSON parsing with error handling
    function safeJSONParse(str, fallback) {
        if (!str) return fallback || null;
        try {
            return JSON.parse(str);
        } catch (e) {
            console.error('JSON parse error:', e.message, 'Input:', str.substring(0, 100));
            return fallback || null;
        }
    }

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

    function formatDate(dateStr) {
        if (!dateStr) return 'N/A';
        try {
            var date = new Date(dateStr);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        } catch (e) {
            return dateStr;
        }
    }

    function getTypeName(typeNum) {
        var types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT',
            28: 'AAAA', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
            50: 'NSEC3', 51: 'NSEC3PARAM', 257: 'CAA'
        };
        return types[typeNum] || ('TYPE' + typeNum);
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Add CNAME indicator to chain visualization
    function addCNAMEIndicator(source, target) {
        // Create CNAME indicator row
        var indicator = document.createElement('div');
        indicator.className = 'cname-indicator';
        indicator.setAttribute('aria-label', 'CNAME from ' + source + ' to ' + target);

        var html = '<span class="zone-indent" aria-hidden="true">' + getIndent(currentDepth) + '</span>';
        html += '<span class="cname-label">\u2192 CNAME</span>';
        html += '<span class="cname-target">' + escapeHtml(target) + '</span>';
        indicator.innerHTML = html;

        chainVisualizationEl.appendChild(indicator);

        // Reset depth for CNAME chain (starts fresh from root)
        currentDepth = 0;
        inCnameChain = true;
    }

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
