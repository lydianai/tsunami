/**
 * XSS Protection Module
 * Provides DOMPurify-like sanitization for preventing XSS attacks
 *
 * Usage:
 *   const clean = XSSProtection.sanitize(userInput);
 *   const element = XSSProtection.createSafeElement('div', { class: 'alert' }, userContent);
 */

const XSSProtection = (function() {
    'use strict';

    // Dangerous HTML tags that should be stripped
    const FORBIDDEN_TAGS = [
        'script', 'iframe', 'object', 'embed', 'applet',
        'link', 'style', 'meta', 'base', 'form'
    ];

    // Dangerous attributes that can execute JavaScript
    const FORBIDDEN_ATTRS = [
        'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
        'onmousemove', 'onmouseenter', 'onmouseleave', 'onfocus', 'onblur',
        'onchange', 'onsubmit', 'onkeydown', 'onkeyup', 'onkeypress',
        'ondblclick', 'oncontextmenu', 'oninput', 'onwheel', 'ondrag',
        'ondrop', 'onscroll', 'onresize', 'onanimationstart', 'onanimationend'
    ];

    // URI schemes that can execute code
    const FORBIDDEN_URI_SCHEMES = [
        'javascript:', 'data:', 'vbscript:', 'file:', 'about:'
    ];

    /**
     * Sanitize HTML string to prevent XSS
     * @param {string} dirty - Untrusted HTML string
     * @param {Object} options - Sanitization options
     * @returns {string} Sanitized HTML string
     */
    function sanitize(dirty, options = {}) {
        if (typeof dirty !== 'string') {
            return '';
        }

        const allowedTags = options.allowedTags || [
            'p', 'br', 'span', 'div', 'a', 'strong', 'em', 'u',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'blockquote', 'code', 'pre',
            'table', 'thead', 'tbody', 'tr', 'td', 'th'
        ];

        const allowedAttrs = options.allowedAttrs || [
            'href', 'title', 'alt', 'class', 'id', 'target', 'rel'
        ];

        // Create temporary DOM element for parsing
        const temp = document.createElement('div');
        temp.innerHTML = dirty;

        // Recursively clean the DOM tree
        cleanNode(temp, allowedTags, allowedAttrs);

        return temp.innerHTML;
    }

    /**
     * Recursively clean DOM node and its children
     * @param {Node} node - DOM node to clean
     * @param {Array} allowedTags - Allowed HTML tags
     * @param {Array} allowedAttrs - Allowed attributes
     */
    function cleanNode(node, allowedTags, allowedAttrs) {
        const children = Array.from(node.childNodes);

        children.forEach(child => {
            if (child.nodeType === Node.ELEMENT_NODE) {
                const tagName = child.tagName.toLowerCase();

                // Remove forbidden tags
                if (FORBIDDEN_TAGS.includes(tagName) || !allowedTags.includes(tagName)) {
                    child.remove();
                    return;
                }

                // Clean attributes
                const attrs = Array.from(child.attributes);
                attrs.forEach(attr => {
                    const attrName = attr.name.toLowerCase();
                    const attrValue = attr.value;

                    // Remove forbidden attributes
                    if (FORBIDDEN_ATTRS.includes(attrName) || !allowedAttrs.includes(attrName)) {
                        child.removeAttribute(attr.name);
                        return;
                    }

                    // Check for dangerous URI schemes
                    if (attrName === 'href' || attrName === 'src') {
                        const lowerValue = attrValue.toLowerCase().trim();
                        if (FORBIDDEN_URI_SCHEMES.some(scheme => lowerValue.startsWith(scheme))) {
                            child.removeAttribute(attr.name);
                            return;
                        }
                    }

                    // Sanitize attribute value
                    child.setAttribute(attr.name, sanitizeAttributeValue(attrValue));
                });

                // Recursively clean children
                cleanNode(child, allowedTags, allowedAttrs);
            } else if (child.nodeType === Node.TEXT_NODE) {
                // Text nodes are safe, keep as-is
            } else {
                // Remove comments and other node types
                child.remove();
            }
        });
    }

    /**
     * Sanitize attribute value
     * @param {string} value - Attribute value
     * @returns {string} Sanitized value
     */
    function sanitizeAttributeValue(value) {
        if (typeof value !== 'string') {
            return '';
        }

        // Decode HTML entities and check for hidden JavaScript
        const decoded = decodeHTMLEntities(value);
        const lowerDecoded = decoded.toLowerCase().trim();

        if (FORBIDDEN_URI_SCHEMES.some(scheme => lowerDecoded.includes(scheme))) {
            return '';
        }

        return value;
    }

    /**
     * Decode HTML entities
     * @param {string} html - HTML string with entities
     * @returns {string} Decoded string
     */
    function decodeHTMLEntities(html) {
        const temp = document.createElement('textarea');
        temp.innerHTML = html;
        return temp.value;
    }

    /**
     * Escape HTML special characters
     * @param {string} str - String to escape
     * @returns {string} Escaped string
     */
    function escapeHTML(str) {
        if (typeof str !== 'string') {
            return '';
        }

        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Create safe DOM element with sanitized content
     * @param {string} tagName - HTML tag name
     * @param {Object} attributes - Element attributes
     * @param {string|Node} content - Element content
     * @returns {HTMLElement} Safe DOM element
     */
    function createSafeElement(tagName, attributes = {}, content = '') {
        // Validate tag name
        if (FORBIDDEN_TAGS.includes(tagName.toLowerCase())) {
            throw new Error(`Forbidden tag: ${tagName}`);
        }

        const element = document.createElement(tagName);

        // Set safe attributes
        Object.entries(attributes).forEach(([key, value]) => {
            const attrName = key.toLowerCase();

            // Skip forbidden attributes
            if (FORBIDDEN_ATTRS.includes(attrName)) {
                return;
            }

            // Validate href/src attributes
            if (attrName === 'href' || attrName === 'src') {
                const lowerValue = String(value).toLowerCase().trim();
                if (FORBIDDEN_URI_SCHEMES.some(scheme => lowerValue.startsWith(scheme))) {
                    return;
                }
            }

            element.setAttribute(key, value);
        });

        // Set content safely
        if (typeof content === 'string') {
            element.textContent = content; // Safe - no HTML parsing
        } else if (content instanceof Node) {
            element.appendChild(content);
        }

        return element;
    }

    /**
     * Safe innerHTML replacement using textContent
     * @param {HTMLElement} element - Target element
     * @param {string} content - Content to set
     */
    function setSafeContent(element, content) {
        if (!(element instanceof HTMLElement)) {
            throw new Error('First argument must be an HTMLElement');
        }

        element.textContent = content;
    }

    /**
     * Safe innerHTML replacement with sanitization
     * @param {HTMLElement} element - Target element
     * @param {string} html - HTML content to set
     * @param {Object} options - Sanitization options
     */
    function setSafeHTML(element, html, options = {}) {
        if (!(element instanceof HTMLElement)) {
            throw new Error('First argument must be an HTMLElement');
        }

        element.innerHTML = sanitize(html, options);
    }

    /**
     * Get CSP nonce from meta tag for inline scripts/styles
     * @returns {string|null} CSP nonce value
     */
    function getCSPNonce() {
        const meta = document.querySelector('meta[property="csp-nonce"]');
        return meta ? meta.getAttribute('content') : null;
    }

    /**
     * Create script element with CSP nonce
     * @param {string} src - Script source URL
     * @param {Object} attributes - Additional attributes
     * @returns {HTMLScriptElement} Script element with nonce
     */
    function createSafeScript(src, attributes = {}) {
        const script = document.createElement('script');
        script.src = src;

        // Add CSP nonce if available
        const nonce = getCSPNonce();
        if (nonce) {
            script.setAttribute('nonce', nonce);
        }

        // Set additional attributes
        Object.entries(attributes).forEach(([key, value]) => {
            if (key !== 'src' && key !== 'nonce') {
                script.setAttribute(key, value);
            }
        });

        return script;
    }

    /**
     * Setup safe event delegation for dynamic content
     * @param {string} selector - CSS selector for target elements
     * @param {string} eventType - Event type (click, submit, etc.)
     * @param {Function} handler - Event handler function
     * @param {HTMLElement} root - Root element for delegation (default: document)
     */
    function delegateEvent(selector, eventType, handler, root = document) {
        root.addEventListener(eventType, function(event) {
            const target = event.target.closest(selector);
            if (target) {
                handler.call(target, event);
            }
        });
    }

    // Public API
    return {
        sanitize,
        escapeHTML,
        createSafeElement,
        setSafeContent,
        setSafeHTML,
        getCSPNonce,
        createSafeScript,
        delegateEvent
    };
})();

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.XSSProtection = XSSProtection;
}
