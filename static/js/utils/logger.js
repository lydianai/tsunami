/**
 * Logger Module
 * Structured logging with environment-aware behavior
 *
 * Usage:
 *   Logger.init({ level: 'info', enableConsole: true });
 *   Logger.debug('Debug message', { data: 'value' });
 *   Logger.info('Info message');
 *   Logger.warn('Warning message');
 *   Logger.error('Error message', error);
 */

const Logger = (function() {
    'use strict';

    // Log levels
    const LEVELS = {
        DEBUG: 0,
        INFO: 1,
        WARN: 2,
        ERROR: 3,
        NONE: 4
    };

    // Configuration
    let config = {
        level: LEVELS.INFO,
        enableConsole: false,
        environment: 'production',
        maxLogs: 100,
        includeTimestamp: true,
        includeStackTrace: false,
        persistLogs: false,
        storageKey: 'app_logs'
    };

    // Log storage
    const logs = [];

    // Original console methods (for restoration)
    const originalConsole = {
        log: console.log,
        debug: console.debug,
        info: console.info,
        warn: console.warn,
        error: console.error
    };

    /**
     * Initialize logger
     * @param {Object} options - Configuration options
     */
    function init(options = {}) {
        config = Object.assign({}, config, options);

        // Set log level from string
        if (typeof config.level === 'string') {
            config.level = LEVELS[config.level.toUpperCase()] || LEVELS.INFO;
        }

        // Disable console in production
        if (!config.enableConsole && config.environment === 'production') {
            disableConsole();
        }

        // Load persisted logs
        if (config.persistLogs) {
            loadPersistedLogs();
        }

        // Log initialization
        log(LEVELS.INFO, 'Logger initialized', {
            level: getLevelName(config.level),
            environment: config.environment
        });
    }

    /**
     * Disable console methods in production
     */
    function disableConsole() {
        console.log = function() {};
        console.debug = function() {};
        console.info = function() {};
        // Keep console.warn and console.error for critical issues
    }

    /**
     * Restore console methods
     */
    function enableConsole() {
        console.log = originalConsole.log;
        console.debug = originalConsole.debug;
        console.info = originalConsole.info;
        console.warn = originalConsole.warn;
        console.error = originalConsole.error;
    }

    /**
     * Get level name from level number
     * @param {number} level - Log level
     * @returns {string} Level name
     */
    function getLevelName(level) {
        for (const [name, value] of Object.entries(LEVELS)) {
            if (value === level) {
                return name;
            }
        }
        return 'UNKNOWN';
    }

    /**
     * Core logging function
     * @param {number} level - Log level
     * @param {string} message - Log message
     * @param {*} data - Additional data
     */
    function log(level, message, data = null) {
        // Check if logging is enabled for this level
        if (level < config.level) {
            return;
        }

        // Create log entry
        const entry = {
            level: getLevelName(level),
            message: message,
            data: data,
            timestamp: config.includeTimestamp ? new Date().toISOString() : null,
            url: window.location.href,
            userAgent: navigator.userAgent
        };

        // Add stack trace for errors
        if (config.includeStackTrace && level >= LEVELS.ERROR) {
            entry.stack = new Error().stack;
        }

        // Store in memory
        logs.push(entry);
        if (logs.length > config.maxLogs) {
            logs.shift(); // Remove oldest log
        }

        // Persist if enabled
        if (config.persistLogs) {
            persistLogs();
        }

        // Output to console if enabled
        if (config.enableConsole) {
            const consoleMethod = getConsoleMethod(level);
            const prefix = `[${entry.level}]`;
            const timestamp = entry.timestamp ? `[${entry.timestamp}]` : '';

            if (data) {
                originalConsole[consoleMethod](prefix, timestamp, message, data);
            } else {
                originalConsole[consoleMethod](prefix, timestamp, message);
            }
        }
    }

    /**
     * Get appropriate console method for log level
     * @param {number} level - Log level
     * @returns {string} Console method name
     */
    function getConsoleMethod(level) {
        switch (level) {
            case LEVELS.DEBUG:
                return 'debug';
            case LEVELS.INFO:
                return 'info';
            case LEVELS.WARN:
                return 'warn';
            case LEVELS.ERROR:
                return 'error';
            default:
                return 'log';
        }
    }

    /**
     * Debug level logging
     * @param {string} message - Log message
     * @param {*} data - Additional data
     */
    function debug(message, data) {
        log(LEVELS.DEBUG, message, data);
    }

    /**
     * Info level logging
     * @param {string} message - Log message
     * @param {*} data - Additional data
     */
    function info(message, data) {
        log(LEVELS.INFO, message, data);
    }

    /**
     * Warning level logging
     * @param {string} message - Log message
     * @param {*} data - Additional data
     */
    function warn(message, data) {
        log(LEVELS.WARN, message, data);
    }

    /**
     * Error level logging
     * @param {string} message - Log message
     * @param {Error|*} error - Error object or data
     */
    function error(message, error) {
        const data = error instanceof Error ? {
            name: error.name,
            message: error.message,
            stack: error.stack
        } : error;

        log(LEVELS.ERROR, message, data);
    }

    /**
     * Log API request
     * @param {string} method - HTTP method
     * @param {string} url - Request URL
     * @param {Object} data - Request/response data
     */
    function logAPI(method, url, data = {}) {
        log(LEVELS.INFO, `API ${method} ${url}`, {
            method: method,
            url: url,
            status: data.status,
            duration: data.duration,
            error: data.error
        });
    }

    /**
     * Log user action
     * @param {string} action - Action name
     * @param {Object} data - Action data
     */
    function logUserAction(action, data = {}) {
        log(LEVELS.INFO, `User action: ${action}`, data);
    }

    /**
     * Log performance metric
     * @param {string} metric - Metric name
     * @param {number} value - Metric value
     * @param {string} unit - Metric unit
     */
    function logPerformance(metric, value, unit = 'ms') {
        log(LEVELS.DEBUG, `Performance: ${metric}`, {
            value: value,
            unit: unit
        });
    }

    /**
     * Get all logs
     * @param {number} level - Optional level filter
     * @returns {Array} Array of log entries
     */
    function getLogs(level = null) {
        if (level !== null) {
            const levelName = getLevelName(level);
            return logs.filter(log => log.level === levelName);
        }
        return logs.slice(); // Return copy
    }

    /**
     * Get logs by level
     * @param {string} levelName - Level name (DEBUG, INFO, WARN, ERROR)
     * @returns {Array} Filtered logs
     */
    function getLogsByLevel(levelName) {
        return logs.filter(log => log.level === levelName.toUpperCase());
    }

    /**
     * Clear all logs
     */
    function clearLogs() {
        logs.length = 0;
        if (config.persistLogs) {
            localStorage.removeItem(config.storageKey);
        }
    }

    /**
     * Persist logs to localStorage
     */
    function persistLogs() {
        try {
            const data = JSON.stringify(logs.slice(-config.maxLogs));
            localStorage.setItem(config.storageKey, data);
        } catch (e) {
            // localStorage might be full or disabled
            originalConsole.warn('[Logger] Failed to persist logs:', e);
        }
    }

    /**
     * Load persisted logs from localStorage
     */
    function loadPersistedLogs() {
        try {
            const data = localStorage.getItem(config.storageKey);
            if (data) {
                const parsed = JSON.parse(data);
                logs.push(...parsed);
            }
        } catch (e) {
            originalConsole.warn('[Logger] Failed to load persisted logs:', e);
        }
    }

    /**
     * Export logs as JSON
     * @returns {string} JSON string of logs
     */
    function exportLogs() {
        return JSON.stringify(logs, null, 2);
    }

    /**
     * Download logs as file
     * @param {string} filename - Download filename
     */
    function downloadLogs(filename = 'logs.json') {
        const data = exportLogs();
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();

        URL.revokeObjectURL(url);
    }

    /**
     * Get log statistics
     * @returns {Object} Statistics object
     */
    function getStats() {
        const stats = {
            total: logs.length,
            byLevel: {
                DEBUG: 0,
                INFO: 0,
                WARN: 0,
                ERROR: 0
            },
            recent: logs.slice(-10).reverse()
        };

        logs.forEach(log => {
            if (stats.byLevel.hasOwnProperty(log.level)) {
                stats.byLevel[log.level]++;
            }
        });

        return stats;
    }

    /**
     * Create logger instance with prefix
     * @param {string} prefix - Log prefix
     * @returns {Object} Logger instance
     */
    function createLogger(prefix) {
        return {
            debug: (msg, data) => debug(`[${prefix}] ${msg}`, data),
            info: (msg, data) => info(`[${prefix}] ${msg}`, data),
            warn: (msg, data) => warn(`[${prefix}] ${msg}`, data),
            error: (msg, error) => error(`[${prefix}] ${msg}`, error)
        };
    }

    /**
     * Time a function execution
     * @param {string} label - Timer label
     * @param {Function} fn - Function to time
     * @returns {*} Function result
     */
    function time(label, fn) {
        const start = performance.now();
        try {
            const result = fn();

            // Handle promises
            if (result && typeof result.then === 'function') {
                return result.finally(() => {
                    const duration = performance.now() - start;
                    logPerformance(label, duration.toFixed(2));
                });
            }

            const duration = performance.now() - start;
            logPerformance(label, duration.toFixed(2));
            return result;
        } catch (e) {
            const duration = performance.now() - start;
            error(`${label} failed after ${duration.toFixed(2)}ms`, e);
            throw e;
        }
    }

    /**
     * Set log level at runtime
     * @param {string|number} level - New log level
     */
    function setLevel(level) {
        if (typeof level === 'string') {
            config.level = LEVELS[level.toUpperCase()] || LEVELS.INFO;
        } else {
            config.level = level;
        }
        info('Log level changed', { level: getLevelName(config.level) });
    }

    /**
     * Enable/disable console output
     * @param {boolean} enabled - Enable console
     */
    function setConsole(enabled) {
        config.enableConsole = enabled;
        if (enabled) {
            enableConsole();
        } else {
            disableConsole();
        }
    }

    // Public API
    return {
        // Initialization
        init,

        // Log methods
        debug,
        info,
        warn,
        error,

        // Specialized logging
        logAPI,
        logUserAction,
        logPerformance,

        // Log management
        getLogs,
        getLogsByLevel,
        clearLogs,
        getStats,
        exportLogs,
        downloadLogs,

        // Utilities
        createLogger,
        time,
        setLevel,
        setConsole,

        // Constants
        LEVELS
    };
})();

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.Logger = Logger;
}
