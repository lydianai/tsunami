# TSUNAMI Frontend - Quick Fixes Implementation Guide

This document contains ready-to-implement fixes for the most critical issues found in the audit.

---

## 1. Create Modular JavaScript Structure

### Step 1: Create directory structure
```bash
mkdir -p /home/lydian/Desktop/TSUNAMI/static/js/{core,modules,utils}
```

### Step 2: Extract Map Manager
**File:** `/home/lydian/Desktop/TSUNAMI/static/js/modules/map-manager.js`

```javascript
/**
 * Map Manager Module
 * Handles Leaflet map initialization and management
 */
export class MapManager {
  constructor(containerId = 'map') {
    this.containerId = containerId;
    this.map = null;
    this.markers = new Map();
    this.layers = new Map();
  }

  async initialize() {
    try {
      const container = document.getElementById(this.containerId);
      if (!container) {
        throw new Error(`Map container #${this.containerId} not found`);
      }

      this.map = L.map(this.containerId, {
        center: [39.0, 35.0],
        zoom: 6,
        zoomControl: true,
        attributionControl: false,
      });

      // Add tile layer
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
      }).addTo(this.map);

      console.log('[MAP] Initialized successfully');
      return this.map;

    } catch (error) {
      console.error('[MAP] Initialization failed:', error);
      this.showError(error.message);
      throw error;
    }
  }

  addMarker(id, lat, lng, options = {}) {
    if (this.markers.has(id)) {
      this.markers.get(id).remove();
    }

    const marker = L.marker([lat, lng], options).addTo(this.map);
    this.markers.set(id, marker);
    return marker;
  }

  removeMarker(id) {
    const marker = this.markers.get(id);
    if (marker) {
      marker.remove();
      this.markers.delete(id);
    }
  }

  showError(message) {
    const container = document.getElementById(this.containerId);
    if (!container) return;

    container.innerHTML = `
      <div class="map-error">
        <span class="error-icon" aria-hidden="true">⚠</span>
        <h3>Map Unavailable</h3>
        <p>${this.escapeHtml(message)}</p>
        <button onclick="location.reload()" class="btn-retry">
          Retry
        </button>
      </div>
    `;
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  destroy() {
    if (this.map) {
      this.map.remove();
      this.map = null;
    }
    this.markers.clear();
    this.layers.clear();
  }
}
```

### Step 3: Create Input Validator Utility
**File:** `/home/lydian/Desktop/TSUNAMI/static/js/utils/validator.js`

```javascript
/**
 * Input Validation Utility
 */
export class InputValidator {
  /**
   * Sanitize user input
   */
  static sanitize(input) {
    if (typeof input !== 'string') return '';
    return input
      .trim()
      .replace(/[<>'"]/g, '') // Remove dangerous characters
      .substring(0, 1000); // Limit length
  }

  /**
   * Validate IP address
   */
  static isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;

    const octets = ip.split('.');
    return octets.every(octet => {
      const num = parseInt(octet, 10);
      return num >= 0 && num <= 255;
    });
  }

  /**
   * Validate domain name
   */
  static isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(domain) && domain.length <= 253;
  }

  /**
   * Validate port number
   */
  static isValidPort(port) {
    const num = parseInt(port, 10);
    return !isNaN(num) && num >= 1 && num <= 65535;
  }

  /**
   * Validate email
   */
  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate URL
   */
  static isValidURL(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }
}
```

### Step 4: Create Event Manager
**File:** `/home/lydian/Desktop/TSUNAMI/static/js/utils/event-manager.js`

```javascript
/**
 * Event Manager - Prevents memory leaks
 */
export class EventManager {
  constructor() {
    this.listeners = [];
  }

  /**
   * Add event listener and track it
   */
  add(target, event, handler, options = {}) {
    target.addEventListener(event, handler, options);
    this.listeners.push({ target, event, handler, options });
  }

  /**
   * Add delegated event listener
   */
  delegate(parent, selector, event, handler) {
    const delegatedHandler = (e) => {
      const target = e.target.closest(selector);
      if (target) {
        handler.call(target, e);
      }
    };

    this.add(parent, event, delegatedHandler);
  }

  /**
   * Remove specific listener
   */
  remove(target, event, handler) {
    target.removeEventListener(event, handler);
    this.listeners = this.listeners.filter(
      listener => !(listener.target === target &&
                    listener.event === event &&
                    listener.handler === handler)
    );
  }

  /**
   * Remove all tracked listeners
   */
  removeAll() {
    this.listeners.forEach(({ target, event, handler }) => {
      target.removeEventListener(event, handler);
    });
    this.listeners = [];
  }

  /**
   * Get count of active listeners
   */
  count() {
    return this.listeners.length;
  }
}
```

### Step 5: Create Logger Utility
**File:** `/home/lydian/Desktop/TSUNAMI/static/js/utils/logger.js`

```javascript
/**
 * Logger Utility - Production-safe logging
 */
export class Logger {
  constructor(context = 'APP') {
    this.context = context;
    this.isDev = this.checkDevMode();
  }

  checkDevMode() {
    // Check if in development mode
    return (
      document.documentElement.dataset.env === 'development' ||
      window.location.hostname === 'localhost' ||
      window.location.hostname === '127.0.0.1'
    );
  }

  log(...args) {
    if (this.isDev) {
      console.log(`[${this.context}]`, ...args);
    }
  }

  info(...args) {
    if (this.isDev) {
      console.info(`[${this.context}]`, ...args);
    }
  }

  warn(...args) {
    if (this.isDev) {
      console.warn(`[${this.context}]`, ...args);
    }
  }

  error(...args) {
    console.error(`[${this.context}]`, ...args);
    // In production, send to error tracking service
    if (!this.isDev) {
      this.reportError(...args);
    }
  }

  debug(...args) {
    if (this.isDev) {
      console.debug(`[${this.context}]`, ...args);
    }
  }

  reportError(...args) {
    // Send to Sentry, LogRocket, or custom endpoint
    // Example:
    // fetch('/api/log-error', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify({ error: args, context: this.context })
    // });
  }
}

// Export singleton instance
export const logger = new Logger();
```

---

## 2. Fix harita.html - Remove Inline Scripts

**File:** `/home/lydian/Desktop/TSUNAMI/templates/harita.html`

Replace the massive inline `<script>` block with:

```html
<!-- At the end of <body>, before </body> -->

<!-- Core utilities -->
<script type="module">
  import { MapManager } from '/static/js/modules/map-manager.js';
  import { InputValidator } from '/static/js/utils/validator.js';
  import { EventManager } from '/static/js/utils/event-manager.js';
  import { logger } from '/static/js/utils/logger.js';

  // Initialize app
  const eventManager = new EventManager();
  let mapManager = null;

  async function initializeApp() {
    try {
      logger.log('Initializing TSUNAMI...');

      // Initialize map
      mapManager = new MapManager('map');
      await mapManager.initialize();

      // Setup event delegation
      setupEventHandlers();

      logger.log('TSUNAMI initialized successfully');
    } catch (error) {
      logger.error('Initialization failed:', error);
    }
  }

  function setupEventHandlers() {
    // Delegate button clicks
    eventManager.delegate(document.body, '[data-action]', 'click', handleAction);

    // Delegate form submissions
    eventManager.delegate(document.body, 'form', 'submit', handleFormSubmit);
  }

  function handleAction(e) {
    e.preventDefault();
    const action = this.dataset.action;
    const handlers = {
      'close-tooltip': closeTooltip,
      'block-ip': blockIP,
      'osint-analyze': osintAnalyze,
      // ... add more handlers
    };

    if (handlers[action]) {
      handlers[action].call(this, e);
    } else {
      logger.warn('Unknown action:', action);
    }
  }

  function handleFormSubmit(e) {
    e.preventDefault();
    const formData = new FormData(this);
    logger.log('Form submitted:', Object.fromEntries(formData));
  }

  // Cleanup on page unload
  window.addEventListener('beforeunload', () => {
    eventManager.removeAll();
    mapManager?.destroy();
  });

  // Start app when DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
  } else {
    initializeApp();
  }
</script>
```

---

## 3. Add Accessibility Attributes

### Fix Buttons
Replace inline onclick buttons with accessible versions:

```html
<!-- BEFORE -->
<button onclick="closeTooltip()">×</button>

<!-- AFTER -->
<button
  data-action="close-tooltip"
  aria-label="Close tooltip"
  class="tooltip-close">
  <span aria-hidden="true">×</span>
</button>
```

### Fix Modal Dialogs
```html
<!-- BEFORE -->
<div class="attack-tooltip" id="attackTooltip">
  <div class="tooltip-close" onclick="closeTooltip()">×</div>
  <div class="tooltip-content">...</div>
</div>

<!-- AFTER -->
<div
  class="attack-tooltip"
  id="attackTooltip"
  role="dialog"
  aria-labelledby="attackTooltipTitle"
  aria-describedby="attackTooltipDesc"
  aria-modal="true"
  hidden>

  <button
    data-action="close-tooltip"
    class="tooltip-close"
    aria-label="Close">
    <span aria-hidden="true">×</span>
  </button>

  <h3 id="attackTooltipTitle">Attack Details</h3>
  <div id="attackTooltipDesc" class="tooltip-content">
    <!-- Content here -->
  </div>
</div>
```

### Add Skip Link
Add at the top of `<body>`:

```html
<a href="#main-content" class="skip-link">
  Skip to main content
</a>

<!-- Then wrap main content -->
<main id="main-content" tabindex="-1">
  <div id="map"></div>
  <!-- ... rest of content -->
</main>
```

---

## 4. Mobile Responsive CSS

**File:** `/home/lydian/Desktop/TSUNAMI/static/css/responsive.css`

```css
/* Mobile First Responsive Styles */

/* Base mobile styles */
.top-bar {
  flex-direction: column;
  padding: 10px;
  gap: 10px;
}

.btn-group {
  flex-wrap: wrap;
  gap: 6px;
  justify-content: center;
}

.btn {
  padding: 12px 20px;
  min-height: 44px;
  font-size: 12px;
}

.side-panel {
  position: relative;
  width: 100%;
  left: 0;
  top: auto;
  max-height: none;
  padding: 10px;
  margin-top: 10px;
}

/* Tablet: 768px and up */
@media (min-width: 768px) {
  .top-bar {
    flex-direction: row;
    padding: 12px 20px;
  }

  .btn-group {
    justify-content: flex-end;
  }

  .side-panel {
    position: fixed;
    width: 220px;
    top: 70px;
    left: 16px;
    max-height: calc(100vh - 180px);
  }
}

/* Desktop: 1024px and up */
@media (min-width: 1024px) {
  .side-panel {
    width: 260px;
  }

  .btn {
    padding: 10px 18px;
    font-size: 11px;
  }
}

/* Large Desktop: 1440px and up */
@media (min-width: 1440px) {
  .side-panel {
    width: 300px;
  }
}

/* Mobile landscape */
@media (max-height: 600px) and (orientation: landscape) {
  .side-panel {
    max-height: calc(100vh - 60px);
  }

  .top-bar {
    padding: 8px 15px;
  }
}

/* Touch device optimizations */
@media (hover: none) and (pointer: coarse) {
  .btn {
    min-height: 48px;
    padding: 14px 24px;
  }

  /* Larger tap targets */
  .tooltip-close,
  .nav-item,
  input,
  select {
    min-height: 44px;
  }
}

/* Reduced motion preference */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

/* High contrast mode */
@media (prefers-contrast: high) {
  :root {
    --text-dim: #a0b0c0;
    --text-normal: #d0e0f0;
    --text-bright: #ffffff;
  }

  .btn {
    border-width: 2px;
  }

  :focus-visible {
    outline: 3px solid currentColor;
    outline-offset: 3px;
  }
}

/* Dark mode preference */
@media (prefers-color-scheme: dark) {
  /* Already using dark theme, but can adjust if needed */
}
```

Add to harita.html head:
```html
<link rel="stylesheet" href="/static/css/responsive.css">
```

---

## 5. Accessibility CSS

**File:** `/home/lydian/Desktop/TSUNAMI/static/css/accessibility.css`

```css
/* Accessibility Enhancements */

/* Screen reader only content */
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
  outline: 3px solid var(--text-bright);
  outline-offset: 2px;
}

/* Focus visible styles */
:focus {
  outline: 2px solid var(--accent-primary);
  outline-offset: 2px;
}

/* Remove outline for mouse users */
:focus:not(:focus-visible) {
  outline: none;
}

/* Enhanced focus for interactive elements */
.btn:focus-visible,
button:focus-visible,
a:focus-visible,
input:focus-visible,
select:focus-visible {
  outline: 2px solid var(--accent-primary);
  outline-offset: 2px;
  box-shadow: 0 0 0 4px rgba(0, 180, 255, 0.2);
}

/* Keyboard navigation indicator */
.keyboard-nav :focus-visible {
  outline: 3px solid var(--hud-cyan);
  outline-offset: 3px;
}

/* Enhanced link visibility */
a:not(.btn) {
  text-decoration: underline;
  text-decoration-skip-ink: auto;
}

a:hover,
a:focus {
  text-decoration-thickness: 2px;
}

/* Better contrast for disabled elements */
:disabled,
[aria-disabled="true"] {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Loading state indicator */
[aria-busy="true"] {
  cursor: wait;
  position: relative;
}

[aria-busy="true"]::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 20px;
  height: 20px;
  border: 2px solid var(--accent-primary);
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: translate(-50%, -50%) rotate(360deg); }
}

/* Error states */
[aria-invalid="true"],
.input-error {
  border-color: var(--accent-danger) !important;
  box-shadow: 0 0 0 3px rgba(255, 51, 85, 0.2);
}

/* Success states */
[aria-invalid="false"],
.input-success {
  border-color: var(--hud-green) !important;
}

/* Live region announcements */
.sr-alert {
  position: absolute;
  left: -10000px;
  width: 1px;
  height: 1px;
  overflow: hidden;
}

[role="alert"],
[role="status"] {
  position: relative;
}

/* High contrast borders */
@media (prefers-contrast: high) {
  .btn,
  input,
  select,
  .panel,
  .card {
    border-width: 2px;
  }

  :focus-visible {
    outline-width: 3px;
    outline-offset: 3px;
  }
}
```

---

## 6. Performance Optimization

### Add Resource Hints
In `<head>` of harita.html:

```html
<!-- Preconnect to external domains -->
<link rel="preconnect" href="https://unpkg.com">
<link rel="preconnect" href="https://cdn.socket.io">
<link rel="preconnect" href="https://d3js.org">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<!-- DNS prefetch as fallback -->
<link rel="dns-prefetch" href="https://unpkg.com">
<link rel="dns-prefetch" href="https://cdn.socket.io">

<!-- Preload critical resources -->
<link rel="preload" href="/static/css/variables.css" as="style">
<link rel="preload" href="/static/js/modules/map-manager.js" as="script">
```

### Defer Non-Critical Scripts
```html
<!-- Critical scripts (load immediately) -->
<script src="/static/js/utils/logger.js" type="module"></script>

<!-- Non-critical scripts (defer) -->
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" defer></script>
<script src="https://unpkg.com/leaflet.markercluster@1.4.1/dist/leaflet.markercluster.js" defer></script>
<script src="https://cdn.socket.io/4.6.0/socket.io.min.js" defer></script>

<!-- Analytics (async) -->
<script src="/static/js/analytics.js" async></script>
```

---

## 7. Flask Server Configuration

**File:** `/home/lydian/Desktop/TSUNAMI/app.py`

Add compression and caching:

```python
from flask import Flask
from flask_compress import Compress

app = Flask(__name__)

# Enable compression
Compress(app)

# Configure cache headers
@app.after_request
def add_cache_headers(response):
    # Cache static files for 1 year
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 31536000
        response.cache_control.public = True

    # Don't cache HTML
    elif request.path.endswith('.html') or request.path == '/':
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True

    return response
```

Install compression:
```bash
pip install flask-compress
```

---

## 8. Testing Checklist

After implementing fixes, test:

### Performance
- [ ] Run Lighthouse audit (target: 90+ score)
- [ ] Check First Contentful Paint < 1.8s
- [ ] Check Time to Interactive < 3.9s
- [ ] Verify gzip compression enabled
- [ ] Test on 3G network throttling

### Accessibility
- [ ] Test with screen reader (NVDA/JAWS/VoiceOver)
- [ ] Navigate entire page with keyboard only
- [ ] Check color contrast with axe DevTools
- [ ] Verify all images have alt text
- [ ] Test with browser zoom at 200%

### Mobile
- [ ] Test on iPhone (Safari)
- [ ] Test on Android (Chrome)
- [ ] Check touch targets >= 44px
- [ ] Verify no horizontal scroll
- [ ] Test in landscape orientation

### Browser Compatibility
- [ ] Chrome (latest)
- [ ] Firefox (latest)
- [ ] Safari (latest)
- [ ] Edge (latest)
- [ ] Chrome Mobile
- [ ] Safari iOS

---

## Deployment Steps

1. **Backup current code**
   ```bash
   cp -r /home/lydian/Desktop/TSUNAMI /home/lydian/Desktop/TSUNAMI_backup
   ```

2. **Install dependencies**
   ```bash
   cd /home/lydian/Desktop/TSUNAMI
   pip install flask-compress
   ```

3. **Create new directories**
   ```bash
   mkdir -p static/js/{modules,utils}
   mkdir -p static/css
   ```

4. **Copy new files**
   - Copy all `.js` files to `static/js/`
   - Copy all `.css` files to `static/css/`

5. **Update HTML templates**
   - Update `<script>` and `<link>` tags
   - Add accessibility attributes
   - Add skip links

6. **Test locally**
   ```bash
   python app.py
   # Visit http://localhost:5000
   # Run tests
   ```

7. **Deploy to production**
   - Run production build (minify CSS/JS)
   - Update environment variable
   - Restart server
   - Monitor error logs

---

## Need Help?

If you encounter issues during implementation:

1. Check browser console for errors
2. Verify all file paths are correct
3. Clear browser cache
4. Test in incognito/private mode
5. Check server logs for backend errors

For questions about specific fixes, refer to the main audit report.
