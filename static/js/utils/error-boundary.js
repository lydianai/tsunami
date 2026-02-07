/**
 * Error Boundary Module
 * Global error handling for JavaScript errors and promise rejections
 *
 * Usage:
 *   ErrorBoundary.init({ reportToServer: true, showUserMessage: true });
 *   ErrorBoundary.captureError(error, context);
 */

const ErrorBoundary = (function() {
    'use strict';

    // Configuration
    let config = {
        reportToServer: false,
        serverEndpoint: '/api/errors',
        showUserMessage: true,
        environment: 'production',
        maxErrors: 50, // Maximum errors to store in memory
        enableConsole: false // Show errors in console (development only)
    };

    // Error storage for analysis
    const errorLog = [];

    // User-friendly error messages
    const USER_MESSAGES = {
        network: 'Network connection issue. Please check your internet connection and try again.',
        timeout: 'The request took too long. Please try again.',
        serverError: 'Server error occurred. Our team has been notified.',
        clientError: 'Something went wrong. Please refresh the page and try again.',
        validationError: 'Please check your input and try again.',
        notFound: 'The requested resource was not found.',
        unauthorized: 'You are not authorized to perform this action.',
        forbidden: 'Access to this resource is forbidden.',
        default: 'An unexpected error occurred. Please try again or contact support.'
    };

    /**
     * Initialize error boundary
     * @param {Object} options - Configuration options
     */
    function init(options = {}) {
        config = Object.assign({}, config, options);

        // Set up global error handler
        window.onerror = handleGlobalError;

        // Set up promise rejection handler
        window.onunhandledrejection = handleUnhandledRejection;

        // Wrap fetch for network error handling
        if (typeof window.fetch !== 'undefined') {
            wrapFetch();
        }

        // Log initialization
        if (config.enableConsole) {
            console.log('[ErrorBoundary] Initialized', config);
        }
    }

    /**
     * Global error handler
     * @param {string} message - Error message
     * @param {string} source - Source file
     * @param {number} lineno - Line number
     * @param {number} colno - Column number
     * @param {Error} error - Error object
     * @returns {boolean} True to prevent default error handling
     */
    function handleGlobalError(message, source, lineno, colno, error) {
        const errorInfo = {
            type: 'javascript_error',
            message: message || 'Unknown error',
            source: source || 'unknown',
            line: lineno || 0,
            column: colno || 0,
            stack: error ? error.stack : null,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };

        captureError(errorInfo);

        // Return true to prevent default browser error handling
        return true;
    }

    /**
     * Unhandled promise rejection handler
     * @param {PromiseRejectionEvent} event - Rejection event
     */
    function handleUnhandledRejection(event) {
        const reason = event.reason;
        const errorInfo = {
            type: 'promise_rejection',
            message: reason ? reason.message || String(reason) : 'Promise rejected',
            stack: reason ? reason.stack : null,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };

        captureError(errorInfo);

        // Prevent default console error
        event.preventDefault();
    }

    /**
     * Wrap fetch to handle network errors
     */
    function wrapFetch() {
        const originalFetch = window.fetch;

        window.fetch = function(...args) {
            return originalFetch.apply(this, args)
                .then(response => {
                    // Handle HTTP errors
                    if (!response.ok) {
                        const errorInfo = {
                            type: 'http_error',
                            message: `HTTP ${response.status}: ${response.statusText}`,
                            status: response.status,
                            statusText: response.statusText,
                            url: args[0],
                            timestamp: new Date().toISOString()
                        };

                        captureError(errorInfo);

                        // Show user message for certain status codes
                        if (config.showUserMessage) {
                            showUserMessage(getMessageForStatus(response.status));
                        }
                    }

                    return response;
                })
                .catch(error => {
                    // Handle network errors
                    const errorInfo = {
                        type: 'network_error',
                        message: error.message || 'Network request failed',
                        stack: error.stack,
                        url: args[0],
                        timestamp: new Date().toISOString()
                    };

                    captureError(errorInfo);

                    if (config.showUserMessage) {
                        showUserMessage(USER_MESSAGES.network);
                    }

                    throw error;
                });
        };
    }

    /**
     * Get user-friendly message for HTTP status code
     * @param {number} status - HTTP status code
     * @returns {string} User message
     */
    function getMessageForStatus(status) {
        if (status === 401) return USER_MESSAGES.unauthorized;
        if (status === 403) return USER_MESSAGES.forbidden;
        if (status === 404) return USER_MESSAGES.notFound;
        if (status === 408) return USER_MESSAGES.timeout;
        if (status >= 400 && status < 500) return USER_MESSAGES.validationError;
        if (status >= 500) return USER_MESSAGES.serverError;
        return USER_MESSAGES.default;
    }

    /**
     * Capture and log error
     * @param {Object} errorInfo - Error information
     * @param {Object} context - Additional context
     */
    function captureError(errorInfo, context = {}) {
        // Add context
        const enrichedError = Object.assign({}, errorInfo, {
            context: context,
            id: generateErrorId()
        });

        // Store in memory (with limit)
        errorLog.push(enrichedError);
        if (errorLog.length > config.maxErrors) {
            errorLog.shift(); // Remove oldest error
        }

        // Log to console in development
        if (config.enableConsole) {
            console.error('[ErrorBoundary] Captured error:', enrichedError);
        }

        // Report to server
        if (config.reportToServer) {
            reportToServer(enrichedError);
        }

        // Show user message
        if (config.showUserMessage && !context.silent) {
            const message = context.userMessage || getUserMessage(errorInfo);
            showUserMessage(message);
        }
    }

    /**
     * Get user-friendly error message
     * @param {Object} errorInfo - Error information
     * @returns {string} User message
     */
    function getUserMessage(errorInfo) {
        if (errorInfo.type === 'network_error') {
            return USER_MESSAGES.network;
        }
        if (errorInfo.type === 'http_error') {
            return getMessageForStatus(errorInfo.status);
        }
        return USER_MESSAGES.default;
    }

    /**
     * Generate unique error ID
     * @returns {string} Unique ID
     */
    function generateErrorId() {
        return Date.now().toString(36) + Math.random().toString(36).substring(2);
    }

    /**
     * Report error to server
     * @param {Object} errorInfo - Error information
     */
    function reportToServer(errorInfo) {
        // Don't report in development
        if (config.environment === 'development') {
            return;
        }

        // Use sendBeacon for reliability (works even when page is unloading)
        if (navigator.sendBeacon) {
            const blob = new Blob([JSON.stringify(errorInfo)], {
                type: 'application/json'
            });
            navigator.sendBeacon(config.serverEndpoint, blob);
        } else {
            // Fallback to fetch
            fetch(config.serverEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(errorInfo),
                keepalive: true
            }).catch(err => {
                // Silently fail - don't create error loop
                if (config.enableConsole) {
                    console.warn('[ErrorBoundary] Failed to report error:', err);
                }
            });
        }
    }

    /**
     * Show user-friendly error message
     * @param {string} message - Error message to display
     */
    function showUserMessage(message) {
        // Remove existing error messages
        const existing = document.querySelectorAll('.error-boundary-message');
        existing.forEach(el => el.remove());

        // Create message element
        const messageEl = document.createElement('div');
        messageEl.className = 'error-boundary-message';
        messageEl.setAttribute('role', 'alert');
        messageEl.setAttribute('aria-live', 'polite');

        // Sanitize message (use textContent for safety)
        messageEl.textContent = message;

        // Styling
        Object.assign(messageEl.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            maxWidth: '400px',
            padding: '16px 20px',
            backgroundColor: '#f8d7da',
            color: '#721c24',
            border: '1px solid #f5c6cb',
            borderRadius: '4px',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
            zIndex: '10000',
            fontSize: '14px',
            lineHeight: '1.5',
            animation: 'slideInRight 0.3s ease-out'
        });

        // Add close button
        const closeBtn = document.createElement('button');
        closeBtn.textContent = '×';
        closeBtn.setAttribute('aria-label', 'Close error message');
        Object.assign(closeBtn.style, {
            position: 'absolute',
            top: '8px',
            right: '8px',
            background: 'none',
            border: 'none',
            fontSize: '24px',
            color: '#721c24',
            cursor: 'pointer',
            padding: '0',
            width: '24px',
            height: '24px',
            lineHeight: '1'
        });

        closeBtn.onclick = function() {
            messageEl.remove();
        };

        messageEl.appendChild(closeBtn);
        document.body.appendChild(messageEl);

        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (messageEl.parentNode) {
                messageEl.remove();
            }
        }, 10000);
    }

    /**
     * Wrap function with error boundary
     * @param {Function} fn - Function to wrap
     * @param {Object} context - Error context
     * @returns {Function} Wrapped function
     */
    function wrap(fn, context = {}) {
        return function(...args) {
            try {
                const result = fn.apply(this, args);

                // Handle promises
                if (result && typeof result.then === 'function') {
                    return result.catch(error => {
                        captureError({
                            type: 'wrapped_error',
                            message: error.message || String(error),
                            stack: error.stack,
                            timestamp: new Date().toISOString()
                        }, context);

                        throw error;
                    });
                }

                return result;
            } catch (error) {
                captureError({
                    type: 'wrapped_error',
                    message: error.message || String(error),
                    stack: error.stack,
                    timestamp: new Date().toISOString()
                }, context);

                throw error;
            }
        };
    }

    /**
     * Get all captured errors
     * @returns {Array} Array of error objects
     */
    function getErrors() {
        return errorLog.slice(); // Return copy
    }

    /**
     * Clear error log
     */
    function clearErrors() {
        errorLog.length = 0;
    }

    /**
     * Get error statistics
     * @returns {Object} Error statistics
     */
    function getStats() {
        const stats = {
            total: errorLog.length,
            byType: {},
            recent: errorLog.slice(-10).reverse()
        };

        errorLog.forEach(error => {
            stats.byType[error.type] = (stats.byType[error.type] || 0) + 1;
        });

        return stats;
    }

    // Add CSS animation for error message
    if (typeof document !== 'undefined') {
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // Public API
    return {
        init,
        captureError,
        wrap,
        getErrors,
        clearErrors,
        getStats,
        showUserMessage
    };
})();

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.ErrorBoundary = ErrorBoundary;
}
