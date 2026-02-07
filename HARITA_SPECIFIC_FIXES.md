# harita.html - Specific Line-by-Line Fixes

This document provides exact fixes for critical issues in harita.html.

---

## File Info
- **Location:** `/home/lydian/Desktop/TSUNAMI/templates/harita.html`
- **Current Size:** 736KB (16,886 lines)
- **Target Size:** < 150KB after modularization

---

## Critical Fix #1: Add Mobile Responsive Meta Tags

**Lines 4-10** - Update meta tags:

```html
<!-- BEFORE -->
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TSUNAMI v3.0 CANLI ÜSTTE - Otonom Siber Komuta Merkezi</title>

<!-- AFTER -->
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#020408">
<meta name="description" content="TSUNAMI Siber Komuta Merkezi - Gerçek Zamanlı Tehdit İzleme">
<title>TSUNAMI v3.0 CANLI ÜSTTE - Otonom Siber Komuta Merkezi</title>

<!-- Add preconnect for performance -->
<link rel="preconnect" href="https://unpkg.com">
<link rel="preconnect" href="https://cdn.socket.io">
<link rel="preconnect" href="https://d3js.org">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
```

---

## Critical Fix #2: Add Responsive CSS

**After line 20** - Add responsive breakpoints:

```css
/* Add to existing <style> block after line 20 */

/* ===== RESPONSIVE DESIGN ===== */
@media (max-width: 768px) {
    /* Mobile: Stack top bar */
    .top-bar {
        flex-direction: column;
        padding: 10px;
        gap: 8px;
    }

    .logo {
        flex-direction: column;
        gap: 8px;
    }

    .logo h1 {
        font-size: 14px;
        letter-spacing: 1px;
    }

    /* Mobile: Full-width button group */
    .btn-group {
        width: 100%;
        flex-wrap: wrap;
        gap: 4px;
        justify-content: center;
    }

    .btn {
        padding: 12px 16px;
        font-size: 10px;
        min-height: 44px; /* iOS minimum touch target */
    }

    /* Mobile: Side panel becomes overlay */
    .side-panel {
        position: fixed;
        top: auto;
        bottom: 0;
        left: 0;
        right: 0;
        width: 100%;
        max-height: 50vh;
        z-index: 2000;
        border-radius: 12px 12px 0 0;
        background: var(--bg-panel);
        backdrop-filter: blur(20px);
        transform: translateY(100%);
        transition: transform 0.3s ease;
    }

    .side-panel.open {
        transform: translateY(0);
    }

    /* Mobile: Larger touch targets */
    .panel {
        padding: 12px;
    }

    .panel-header {
        font-size: 11px;
        padding: 10px;
    }

    /* Mobile: Terminal bar full width */
    .terminal-bar {
        bottom: 0;
        left: 0;
        right: 0;
        width: 100%;
    }

    /* Mobile: Tooltips centered */
    .attack-tooltip {
        left: 50% !important;
        top: 50% !important;
        transform: translate(-50%, -50%) !important;
        width: 90%;
        max-width: 400px;
    }
}

/* Tablet breakpoint */
@media (min-width: 769px) and (max-width: 1024px) {
    .side-panel {
        width: 200px;
    }

    .btn {
        padding: 8px 14px;
        font-size: 10px;
    }
}

/* Large desktop */
@media (min-width: 1440px) {
    .side-panel {
        width: 280px;
    }
}

/* Touch device optimizations */
@media (hover: none) and (pointer: coarse) {
    .btn,
    button,
    .nav-item {
        min-height: 48px;
        padding: 14px 20px;
    }

    /* Larger close buttons */
    .tooltip-close,
    .panel-close {
        width: 44px;
        height: 44px;
        font-size: 24px;
    }
}

/* Landscape mobile */
@media (max-height: 600px) and (orientation: landscape) {
    .side-panel {
        max-height: calc(100vh - 60px);
    }

    .top-bar {
        padding: 6px 15px;
    }
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
}
```

---

## Critical Fix #3: Add Accessibility Attributes

**Lines 5348-5380** - Fix tooltip buttons:

```html
<!-- BEFORE (Line 5348) -->
<div class="attack-tooltip" id="attackTooltip" onclick="event.stopPropagation();">
    <div class="tooltip-close" onclick="closeTooltip()">&times;</div>

<!-- AFTER -->
<div
    class="attack-tooltip"
    id="attackTooltip"
    role="dialog"
    aria-labelledby="tooltipTitle"
    aria-describedby="tooltipDesc"
    aria-modal="true"
    hidden>
    <button
        data-action="close-tooltip"
        class="tooltip-close"
        aria-label="Close attack details"
        type="button">
        <span aria-hidden="true">&times;</span>
    </button>
```

**Lines 5362-5381** - Fix action buttons:

```html
<!-- BEFORE (Lines 5362-5364) -->
<button class="tt-btn danger" onclick="ipEngelle()">
    <svg>...</svg> Engelle
</button>
<button class="tt-btn primary" onclick="osintAnaliz()">
    <svg>...</svg> OSINT
</button>

<!-- AFTER -->
<button
    class="tt-btn danger"
    data-action="block-ip"
    aria-label="Block this IP address"
    type="button">
    <svg aria-hidden="true">...</svg>
    <span>Engelle</span>
</button>
<button
    class="tt-btn primary"
    data-action="osint-analyze"
    aria-label="Run OSINT analysis"
    type="button">
    <svg aria-hidden="true">...</svg>
    <span>OSINT</span>
</button>
```

---

## Critical Fix #4: Add Focus Styles

**After line 500** - Add focus management:

```css
/* Add to existing <style> block */

/* ===== ACCESSIBILITY - FOCUS STYLES ===== */
:focus {
    outline: 2px solid var(--accent-primary);
    outline-offset: 2px;
}

:focus:not(:focus-visible) {
    outline: none;
}

.btn:focus-visible,
button:focus-visible,
a:focus-visible {
    outline: 2px solid var(--accent-primary);
    outline-offset: 2px;
    box-shadow: 0 0 0 4px rgba(0, 180, 255, 0.2);
}

/* Skip link */
.skip-link {
    position: absolute;
    top: -40px;
    left: 0;
    background: var(--accent-primary);
    color: var(--bg-void);
    padding: 8px 16px;
    text-decoration: none;
    font-weight: bold;
    z-index: 10000;
    border-radius: 0 0 4px 0;
}

.skip-link:focus {
    top: 0;
}

/* Screen reader only */
.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
}
```

---

## Critical Fix #5: Add Mobile Menu Toggle

**After the opening `<body>` tag** - Add skip link and mobile menu:

```html
<!-- Add immediately after <body> tag -->
<a href="#map" class="skip-link">
    Skip to map
</a>

<!-- Add mobile menu toggle button (shown only on mobile) -->
<button
    class="mobile-menu-toggle"
    aria-label="Open menu"
    aria-expanded="false"
    aria-controls="mobileNav"
    style="display: none;">
    <span></span>
    <span></span>
    <span></span>
</button>
```

Add corresponding CSS:

```css
/* Add to <style> block */

/* Mobile menu toggle */
.mobile-menu-toggle {
    position: fixed;
    top: 15px;
    right: 15px;
    z-index: 3000;
    background: var(--bg-panel);
    border: 1px solid var(--border-glow);
    border-radius: 6px;
    padding: 10px;
    width: 44px;
    height: 44px;
    display: none;
    flex-direction: column;
    justify-content: space-around;
    align-items: center;
}

.mobile-menu-toggle span {
    display: block;
    width: 24px;
    height: 2px;
    background: var(--text-bright);
    transition: all 0.3s ease;
}

.mobile-menu-toggle[aria-expanded="true"] span:nth-child(1) {
    transform: rotate(45deg) translateY(8px);
}

.mobile-menu-toggle[aria-expanded="true"] span:nth-child(2) {
    opacity: 0;
}

.mobile-menu-toggle[aria-expanded="true"] span:nth-child(3) {
    transform: rotate(-45deg) translateY(-8px);
}

@media (max-width: 768px) {
    .mobile-menu-toggle {
        display: flex;
    }

    .btn-group {
        position: fixed;
        top: 60px;
        right: -100%;
        width: 80%;
        max-width: 300px;
        height: calc(100vh - 60px);
        background: var(--bg-panel);
        backdrop-filter: blur(20px);
        border-left: 1px solid var(--border-glow);
        flex-direction: column;
        padding: 20px;
        transition: right 0.3s ease;
        z-index: 2999;
    }

    .btn-group.open {
        right: 0;
    }

    .btn-group .btn {
        width: 100%;
        justify-content: flex-start;
    }
}
```

---

## Critical Fix #6: Fix Input Validation

**Lines 15235-15262** - Add validation to checkIOC function:

```javascript
// BEFORE (Line 15235)
async function checkIOC() {
    const ioc = document.getElementById('iocCheckInput').value;
    if (!ioc) return alert('IOC gerekli');

// AFTER
async function checkIOC() {
    const rawInput = document.getElementById('iocCheckInput').value;

    // Sanitize input
    const ioc = rawInput.trim().replace(/[<>'"]/g, '').substring(0, 1000);

    if (!ioc) {
        showNotification('IOC gerekli', 'error');
        return;
    }

    // Validate format
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(ioc);
    const isDomain = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(ioc);

    if (!isIP && !isDomain) {
        showNotification('Geçersiz IP veya domain formatı', 'error');
        return;
    }

    // Additional IP validation
    if (isIP) {
        const octets = ioc.split('.');
        const valid = octets.every(octet => {
            const num = parseInt(octet, 10);
            return num >= 0 && num <= 255;
        });

        if (!valid) {
            showNotification('Geçersiz IP adresi', 'error');
            return;
        }
    }

    const resultDiv = document.getElementById('iocCheckResult');
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<div style="color:var(--text-dim)">Kontrol ediliyor...</div>';
    resultDiv.setAttribute('aria-live', 'polite');
    resultDiv.setAttribute('aria-busy', 'true');

    try {
        const endpoint = isIP ? `/api/threat-intel/check/ip/${encodeURIComponent(ioc)}` : `/api/threat-intel/check/domain/${encodeURIComponent(ioc)}`;

        const res = await fetch(endpoint);
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const data = await res.json();

        if (data.basarili) {
            const riskColor = data.risk_skoru > 70 ? 'var(--accent-danger)' :
                            data.risk_skoru > 40 ? 'var(--accent-warning)' :
                            'var(--hud-green)';

            const safeMessage = escapeHtml(data.mesaj || 'Kontrol tamamlandı');

            resultDiv.innerHTML = `
                <div style="color:${riskColor};font-size:18px;font-weight:bold" role="status">
                    Risk: ${data.risk_skoru || 0}%
                </div>
                <div style="font-size:10px;color:var(--text-dim);margin-top:5px">
                    ${safeMessage}
                </div>
            `;
        } else {
            const safeError = escapeHtml(data.hata || 'Kontrol başarısız');
            resultDiv.innerHTML = `<div style="color:var(--accent-danger)" role="alert">${safeError}</div>`;
        }
    } catch (e) {
        logger.error('[IOC] Check failed:', e);
        resultDiv.innerHTML = '<div style="color:var(--accent-danger)" role="alert">Bağlantı hatası</div>';
    } finally {
        resultDiv.removeAttribute('aria-busy');
    }
}

// Helper function for HTML escaping
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Helper function for notifications
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.setAttribute('role', type === 'error' ? 'alert' : 'status');
    notification.textContent = message;

    document.body.appendChild(notification);

    // Auto-remove after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}
```

---

## Critical Fix #7: Event Delegation

**Lines 7220-7300** - Replace inline handlers with delegation:

```javascript
// BEFORE (scattered inline onclick handlers)
// onclick="closeTooltip()"
// onclick="ipEngelle()"
// etc.

// AFTER - Add to DOMContentLoaded section (around line 7220)
document.addEventListener('DOMContentLoaded', async () => {
    // ... existing init code ...

    // Event delegation for all buttons
    document.addEventListener('click', handleGlobalClick);

    // Form submission handler
    document.addEventListener('submit', handleFormSubmit);

    // Cleanup on unload
    window.addEventListener('beforeunload', cleanup);
});

/**
 * Global click handler with event delegation
 */
function handleGlobalClick(e) {
    const target = e.target.closest('[data-action]');
    if (!target) return;

    const action = target.dataset.action;
    const handlers = {
        'close-tooltip': closeTooltip,
        'block-ip': ipEngelle,
        'osint-analyze': osintAnaliz,
        'create-report': raporOlustur,
        'ai-analyze': aiSaldiriAnaliz,
        'counter-attack': karsiSaldiri,
        'watch-attack': saldiriIzle,
        'shodan-scan': shodanScan,
        'find-towers': findNearbyTowers,
        'find-vulns': findVulnDevices,
        'siber-analyze': siberAnaliz,
        'threat-hunt': siberTehditAvi,
        'agent-task': siberAjanGorev,
        'airspace': siberHavaSahasi,
        'close-sv': closeSV,
        'toggle-tor': activateTorStealth,
        // ... add more handlers
    };

    const handler = handlers[action];
    if (handler) {
        e.preventDefault();
        handler.call(target, e);
    } else {
        console.warn('[EVENT] Unknown action:', action);
    }
}

/**
 * Form submission handler
 */
function handleFormSubmit(e) {
    const form = e.target;
    if (!form.checkValidity()) {
        e.preventDefault();
        showNotification('Lütfen tüm alanları doldurun', 'error');
        return;
    }

    // Handle specific forms
    const formId = form.id;
    if (formId === 'osintForm') {
        e.preventDefault();
        handleOSINTSubmit(form);
    } else if (formId === 'shodanForm') {
        e.preventDefault();
        handleShodanSubmit(form);
    }
    // ... handle other forms
}

/**
 * Cleanup function
 */
function cleanup() {
    // Remove event listeners
    document.removeEventListener('click', handleGlobalClick);
    document.removeEventListener('submit', handleFormSubmit);

    // Clear intervals
    if (typeof attackInterval !== 'undefined') {
        clearInterval(attackInterval);
    }

    // Disconnect socket
    if (typeof socket !== 'undefined' && socket.connected) {
        socket.disconnect();
    }

    console.log('[CLEANUP] Resources cleaned up');
}
```

---

## Critical Fix #8: Add Error Boundaries

**Lines 7320 and 7416** - Improve error handling:

```javascript
// BEFORE (Line 7320)
} catch (e) {
    console.error('[MAP] Init error:', e);
    document.getElementById('map').innerHTML = '<div style="...">⚠ Harita kütüphanesi yüklenemedi</div>';
}

// AFTER
} catch (e) {
    console.error('[MAP] Init error:', e);
    showMapError(e);
    reportError('map_init_failed', e);
}

/**
 * Show map error with fallback UI
 */
function showMapError(error) {
    const mapEl = document.getElementById('map');
    if (!mapEl) return;

    const errorMessage = escapeHtml(error.message || 'Bilinmeyen hata');

    mapEl.innerHTML = `
        <div class="map-error" role="alert">
            <div class="error-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="48" height="48">
                    <path fill="currentColor" d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
                </svg>
            </div>
            <h2>Map Unavailable</h2>
            <p>${errorMessage}</p>
            <div class="error-actions">
                <button onclick="location.reload()" class="btn btn-primary">
                    Retry
                </button>
                <button onclick="showMapDiagnostics()" class="btn btn-secondary">
                    Diagnostics
                </button>
            </div>
            <details class="error-details">
                <summary>Technical Details</summary>
                <pre>${escapeHtml(error.stack || 'No stack trace')}</pre>
            </details>
        </div>
    `;
}

/**
 * Report error to monitoring service
 */
function reportError(category, error) {
    // Send to error tracking service (Sentry, etc.)
    const errorData = {
        category,
        message: error.message,
        stack: error.stack,
        url: window.location.href,
        userAgent: navigator.userAgent,
        timestamp: new Date().toISOString(),
    };

    // Example: Send to backend
    fetch('/api/log-error', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(errorData),
    }).catch(() => {
        // Silently fail if logging fails
        console.error('[ERROR] Failed to report error');
    });
}

/**
 * Show diagnostics for troubleshooting
 */
function showMapDiagnostics() {
    const diagnostics = {
        'Leaflet Loaded': typeof L !== 'undefined',
        'Socket.IO Loaded': typeof io !== 'undefined',
        'D3 Loaded': typeof d3 !== 'undefined',
        'Local Storage': (() => {
            try {
                localStorage.setItem('test', 'test');
                localStorage.removeItem('test');
                return 'Available';
            } catch {
                return 'Blocked';
            }
        })(),
        'Online': navigator.onLine,
        'Screen': `${screen.width}x${screen.height}`,
        'Viewport': `${window.innerWidth}x${window.innerHeight}`,
    };

    alert('System Diagnostics:\n\n' +
        Object.entries(diagnostics)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n')
    );
}
```

---

## Performance Fix: Defer Scripts

**Lines 15-19** - Update script loading:

```html
<!-- BEFORE -->
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.markercluster@1.4.1/dist/leaflet.markercluster.js"></script>
<script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
<script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
<script src="https://d3js.org/d3.v7.min.js"></script>

<!-- AFTER -->
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" defer></script>
<script src="https://unpkg.com/leaflet.markercluster@1.4.1/dist/leaflet.markercluster.js" defer></script>
<script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js" defer></script>
<script src="https://cdn.socket.io/4.6.0/socket.io.min.js" defer></script>
<script src="https://d3js.org/d3.v7.min.js" defer></script>
```

---

## CSS Optimization: Remove !important

**Throughout file** - Replace !important with proper specificity:

```css
/* BEFORE */
[data-theme="cockpit-bw"] .theme-toggle {
    background: rgba(0,0,0,0.9) !important;
    border-color: rgba(255,255,255,0.5) !important;
}

/* AFTER */
.theme-toggle[data-theme="cockpit-bw"],
[data-theme="cockpit-bw"].theme-toggle {
    background: rgba(0,0,0,0.9);
    border-color: rgba(255,255,255,0.5);
}
```

---

## Testing Script

Add this to test the fixes:

```javascript
// Add to end of main script block
// TEST SCRIPT - Remove in production
if (window.location.hostname === 'localhost') {
    console.log('Running diagnostics...');

    // Test 1: Check all required libraries loaded
    const libs = {
        Leaflet: typeof L !== 'undefined',
        SocketIO: typeof io !== 'undefined',
        D3: typeof d3 !== 'undefined',
    };
    console.table(libs);

    // Test 2: Check accessibility
    const a11yIssues = [];
    document.querySelectorAll('button:not([aria-label])').forEach(btn => {
        if (!btn.textContent.trim()) {
            a11yIssues.push(`Button without label: ${btn.className}`);
        }
    });
    if (a11yIssues.length) {
        console.warn('A11Y Issues:', a11yIssues);
    }

    // Test 3: Check mobile responsiveness
    const isMobile = window.innerWidth < 768;
    console.log('Mobile view:', isMobile);

    // Test 4: Performance metrics
    if (window.performance) {
        setTimeout(() => {
            const perf = performance.getEntriesByType('navigation')[0];
            console.log('Performance:', {
                'DOM Content Loaded': Math.round(perf.domContentLoadedEventEnd - perf.domContentLoadedEventStart) + 'ms',
                'Load Complete': Math.round(perf.loadEventEnd - perf.loadEventStart) + 'ms',
            });
        }, 2000);
    }
}
```

---

## Validation Checklist

After applying fixes:

- [ ] File size reduced from 736KB
- [ ] All buttons have aria-label or text content
- [ ] Mobile menu works on < 768px screens
- [ ] Touch targets are at least 44px
- [ ] No inline onclick handlers remain
- [ ] Focus indicators visible
- [ ] Skip link works
- [ ] Inputs have validation
- [ ] Error handling implemented
- [ ] Scripts deferred
- [ ] Console logs removed/controlled

---

## Next Steps

1. Apply these fixes incrementally
2. Test after each major change
3. Use browser DevTools to verify
4. Run Lighthouse audit
5. Test with screen reader
6. Deploy to staging first

For complete implementation guide, see QUICK_FIXES.md.
