/**
 * Main Application Entry Point
 * Initializes all security modules and application features
 *
 * Load order:
 * 1. Logger (for debugging initialization)
 * 2. Error Boundary (catch errors during initialization)
 * 3. XSS Protection (before any DOM manipulation)
 * 4. Input Validator (for forms)
 * 5. Application features
 */

(function() {
    'use strict';

    // Configuration
    const APP_CONFIG = {
        environment: detectEnvironment(),
        version: '1.0.0',
        enableServiceWorker: false, // Set to true to enable
        cspNonce: getCSPNonce()
    };

    /**
     * Detect environment (development/production)
     * @returns {string} Environment name
     */
    function detectEnvironment() {
        const hostname = window.location.hostname;

        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.startsWith('192.168.')) {
            return 'development';
        }

        return 'production';
    }

    /**
     * Get CSP nonce from meta tag
     * @returns {string|null} CSP nonce
     */
    function getCSPNonce() {
        const meta = document.querySelector('meta[property="csp-nonce"]');
        return meta ? meta.getAttribute('content') : null;
    }

    /**
     * Initialize Logger
     */
    function initLogger() {
        if (typeof Logger === 'undefined') {
            console.warn('[Main] Logger module not loaded');
            return;
        }

        Logger.init({
            level: APP_CONFIG.environment === 'development' ? 'debug' : 'info',
            enableConsole: APP_CONFIG.environment === 'development',
            environment: APP_CONFIG.environment,
            maxLogs: 100,
            includeTimestamp: true,
            persistLogs: APP_CONFIG.environment === 'development'
        });

        Logger.info('Application starting', {
            environment: APP_CONFIG.environment,
            version: APP_CONFIG.version,
            userAgent: navigator.userAgent
        });
    }

    /**
     * Initialize Error Boundary
     */
    function initErrorBoundary() {
        if (typeof ErrorBoundary === 'undefined') {
            console.warn('[Main] ErrorBoundary module not loaded');
            return;
        }

        ErrorBoundary.init({
            reportToServer: APP_CONFIG.environment === 'production',
            serverEndpoint: '/api/errors',
            showUserMessage: true,
            environment: APP_CONFIG.environment,
            maxErrors: 50,
            enableConsole: APP_CONFIG.environment === 'development'
        });

        Logger.info('Error boundary initialized');
    }

    /**
     * Initialize XSS Protection
     */
    function initXSSProtection() {
        if (typeof XSSProtection === 'undefined') {
            Logger.warn('XSSProtection module not loaded');
            return;
        }

        // Set up safe event delegation for dynamic content
        // Example: Handle dynamically added buttons
        XSSProtection.delegateEvent('[data-action]', 'click', function(event) {
            event.preventDefault();
            const action = this.getAttribute('data-action');
            Logger.logUserAction('Button click', { action: action });
            // Handle action...
        });

        // Inject CSP nonce into existing inline scripts if needed
        if (APP_CONFIG.cspNonce) {
            const inlineScripts = document.querySelectorAll('script:not([src]):not([nonce])');
            inlineScripts.forEach(script => {
                script.setAttribute('nonce', APP_CONFIG.cspNonce);
            });
        }

        Logger.info('XSS protection initialized');
    }

    /**
     * Initialize Input Validators
     */
    function initInputValidators() {
        if (typeof InputValidator === 'undefined') {
            Logger.warn('InputValidator module not loaded');
            return;
        }

        // Auto-attach validators to inputs with data-validate attribute
        const inputs = document.querySelectorAll('[data-validate]');

        inputs.forEach(input => {
            const validationType = input.getAttribute('data-validate');
            const options = {
                showFeedback: true,
                debounce: 300,
                validateOnLoad: false
            };

            // Check for additional validation attributes
            if (input.hasAttribute('data-min-length')) {
                options.minLength = parseInt(input.getAttribute('data-min-length'), 10);
            }
            if (input.hasAttribute('data-max-length')) {
                options.maxLength = parseInt(input.getAttribute('data-max-length'), 10);
            }

            InputValidator.attachValidator(input, validationType, options);
        });

        // Prevent invalid form submissions
        const forms = document.querySelectorAll('form[data-validate-form]');
        forms.forEach(form => {
            InputValidator.preventInvalidSubmission(form);
        });

        Logger.info('Input validators initialized', {
            inputCount: inputs.length,
            formCount: forms.length
        });
    }

    /**
     * Initialize Service Worker (optional)
     */
    function initServiceWorker() {
        if (!APP_CONFIG.enableServiceWorker) {
            return;
        }

        if ('serviceWorker' in navigator && APP_CONFIG.environment === 'production') {
            window.addEventListener('load', function() {
                navigator.serviceWorker.register('/service-worker.js')
                    .then(function(registration) {
                        Logger.info('Service Worker registered', {
                            scope: registration.scope
                        });
                    })
                    .catch(function(error) {
                        Logger.error('Service Worker registration failed', error);
                    });
            });
        }
    }

    /**
     * Initialize performance monitoring
     */
    function initPerformanceMonitoring() {
        if (!window.performance || !window.performance.timing) {
            return;
        }

        window.addEventListener('load', function() {
            // Wait for all resources to load
            setTimeout(function() {
                const timing = performance.timing;
                const loadTime = timing.loadEventEnd - timing.navigationStart;
                const domReadyTime = timing.domContentLoadedEventEnd - timing.navigationStart;
                const connectTime = timing.responseEnd - timing.requestStart;

                Logger.logPerformance('Page load', loadTime);
                Logger.logPerformance('DOM ready', domReadyTime);
                Logger.logPerformance('Server response', connectTime);

                // Log performance entries
                if (performance.getEntriesByType) {
                    const resources = performance.getEntriesByType('resource');
                    const slowResources = resources.filter(r => r.duration > 1000);

                    if (slowResources.length > 0) {
                        Logger.warn('Slow resources detected', {
                            count: slowResources.length,
                            resources: slowResources.map(r => ({
                                name: r.name,
                                duration: r.duration.toFixed(2)
                            }))
                        });
                    }
                }
            }, 0);
        });
    }

    /**
     * Initialize security headers check
     */
    function checkSecurityHeaders() {
        // Check for important meta tags
        const requiredMeta = [
            { name: 'viewport', expected: true },
            { name: 'X-UA-Compatible', expected: false } // Not needed for modern sites
        ];

        requiredMeta.forEach(meta => {
            const element = document.querySelector(`meta[name="${meta.name}"]`);
            if (!element && meta.expected) {
                Logger.warn(`Missing meta tag: ${meta.name}`);
            }
        });

        // Check CSP nonce
        if (!APP_CONFIG.cspNonce && APP_CONFIG.environment === 'production') {
            Logger.warn('CSP nonce not found - inline scripts may be blocked');
        }
    }

    /**
     * Setup AJAX request interceptors
     */
    function setupAJAXInterceptors() {
        // Intercept jQuery AJAX if available
        if (typeof jQuery !== 'undefined') {
            jQuery(document).ajaxStart(function() {
                Logger.debug('AJAX request started');
            });

            jQuery(document).ajaxComplete(function(event, xhr, settings) {
                Logger.logAPI(
                    settings.type || 'GET',
                    settings.url,
                    { status: xhr.status }
                );
            });

            jQuery(document).ajaxError(function(event, xhr, settings, error) {
                Logger.error('AJAX request failed', {
                    method: settings.type || 'GET',
                    url: settings.url,
                    status: xhr.status,
                    error: error
                });
            });
        }

        // Wrap fetch for logging (already wrapped by ErrorBoundary)
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const startTime = performance.now();

            return originalFetch.apply(this, args)
                .then(response => {
                    const duration = performance.now() - startTime;
                    Logger.logAPI(
                        args[1]?.method || 'GET',
                        args[0],
                        {
                            status: response.status,
                            duration: duration.toFixed(2)
                        }
                    );
                    return response;
                })
                .catch(error => {
                    const duration = performance.now() - startTime;
                    Logger.logAPI(
                        args[1]?.method || 'GET',
                        args[0],
                        {
                            error: error.message,
                            duration: duration.toFixed(2)
                        }
                    );
                    throw error;
                });
        };
    }

    /**
     * Initialize accessibility features
     */
    function initAccessibility() {
        // Add skip to main content link if not present
        if (!document.querySelector('[href="#main-content"]')) {
            const skipLink = document.createElement('a');
            skipLink.href = '#main-content';
            skipLink.textContent = 'Skip to main content';
            skipLink.className = 'skip-link';
            skipLink.style.cssText = `
                position: absolute;
                top: -40px;
                left: 0;
                background: #000;
                color: #fff;
                padding: 8px;
                text-decoration: none;
                z-index: 100;
            `;
            skipLink.addEventListener('focus', function() {
                this.style.top = '0';
            });
            skipLink.addEventListener('blur', function() {
                this.style.top = '-40px';
            });
            document.body.insertBefore(skipLink, document.body.firstChild);
        }

        // Ensure main content has ID
        const main = document.querySelector('main') || document.querySelector('[role="main"]');
        if (main && !main.id) {
            main.id = 'main-content';
        }

        Logger.debug('Accessibility features initialized');
    }

    /**
     * Initialize application features
     */
    function initAppFeatures() {
        // Application-specific initialization
        Logger.debug('Initializing application features');

        // Example: Initialize tooltips, modals, etc.
        // This is where you'd initialize any UI libraries or custom components
    }

    /**
     * Main initialization function
     */
    function init() {
        try {
            // 1. Initialize logger first (for debugging)
            initLogger();

            // 2. Initialize error boundary (catch errors during init)
            initErrorBoundary();

            // 3. Check security configuration
            checkSecurityHeaders();

            // 4. Initialize security modules
            initXSSProtection();
            initInputValidators();

            // 5. Setup monitoring
            initPerformanceMonitoring();
            setupAJAXInterceptors();

            // 6. Initialize accessibility
            initAccessibility();

            // 7. Initialize service worker (if enabled)
            initServiceWorker();

            // 8. Initialize app features
            initAppFeatures();

            Logger.info('Application initialized successfully', {
                modules: [
                    'Logger',
                    'ErrorBoundary',
                    'XSSProtection',
                    'InputValidator'
                ]
            });

            // Dispatch custom event for other scripts
            window.dispatchEvent(new CustomEvent('app:initialized', {
                detail: { config: APP_CONFIG }
            }));

        } catch (error) {
            console.error('[Main] Initialization error:', error);

            if (typeof ErrorBoundary !== 'undefined') {
                ErrorBoundary.captureError({
                    type: 'initialization_error',
                    message: error.message,
                    stack: error.stack,
                    timestamp: new Date().toISOString()
                });
            }
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        // DOM already loaded
        init();
    }

    // Expose public API
    window.App = {
        config: APP_CONFIG,
        version: APP_CONFIG.version,
        environment: APP_CONFIG.environment
    };

})();
