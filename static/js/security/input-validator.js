/**
 * Input Validator Module
 * Client-side validation for common input types
 *
 * Usage:
 *   InputValidator.validateIP('192.168.1.1'); // returns { valid: true, message: '' }
 *   InputValidator.attachValidator(inputElement, 'email');
 *   InputValidator.validateForm(formElement);
 */

const InputValidator = (function() {
    'use strict';

    // Validation patterns
    const PATTERNS = {
        // IPv4: 0.0.0.0 to 255.255.255.255
        ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,

        // IPv6: Full and compressed formats
        ipv6: /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,

        // CIDR notation: IP/prefix
        cidr: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/,

        // Domain name
        domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,

        // Email address (RFC 5322 simplified)
        email: /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,

        // Phone number (international format)
        phone: /^[+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}$/,

        // URL
        url: /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/,

        // MAC address
        mac: /^(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})$/,

        // Port number
        port: /^(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$/,

        // Alphanumeric only
        alphanumeric: /^[a-zA-Z0-9]+$/,

        // Alphanumeric with spaces and basic punctuation
        text: /^[a-zA-Z0-9\s\.,!?;:'\-]+$/
    };

    /**
     * Validate IP address (IPv4 or IPv6)
     * @param {string} value - IP address to validate
     * @returns {Object} Validation result { valid: boolean, message: string }
     */
    function validateIP(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'IP address is required' };
        }

        const trimmed = value.trim();

        if (PATTERNS.ipv4.test(trimmed)) {
            return { valid: true, message: '' };
        }

        if (PATTERNS.ipv6.test(trimmed)) {
            return { valid: true, message: '' };
        }

        return { valid: false, message: 'Invalid IP address format' };
    }

    /**
     * Validate CIDR notation
     * @param {string} value - CIDR to validate
     * @returns {Object} Validation result
     */
    function validateCIDR(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'CIDR notation is required' };
        }

        const trimmed = value.trim();

        if (!PATTERNS.cidr.test(trimmed)) {
            return { valid: false, message: 'Invalid CIDR notation (e.g., 192.168.1.0/24)' };
        }

        return { valid: true, message: '' };
    }

    /**
     * Validate domain name
     * @param {string} value - Domain to validate
     * @returns {Object} Validation result
     */
    function validateDomain(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'Domain name is required' };
        }

        const trimmed = value.trim();

        if (trimmed.length > 253) {
            return { valid: false, message: 'Domain name too long (max 253 characters)' };
        }

        if (!PATTERNS.domain.test(trimmed)) {
            return { valid: false, message: 'Invalid domain name format' };
        }

        return { valid: true, message: '' };
    }

    /**
     * Validate email address
     * @param {string} value - Email to validate
     * @returns {Object} Validation result
     */
    function validateEmail(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'Email address is required' };
        }

        const trimmed = value.trim();

        if (trimmed.length > 254) {
            return { valid: false, message: 'Email address too long' };
        }

        if (!PATTERNS.email.test(trimmed)) {
            return { valid: false, message: 'Invalid email address format' };
        }

        return { valid: true, message: '' };
    }

    /**
     * Validate phone number
     * @param {string} value - Phone number to validate
     * @returns {Object} Validation result
     */
    function validatePhone(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'Phone number is required' };
        }

        const trimmed = value.trim();

        if (!PATTERNS.phone.test(trimmed)) {
            return { valid: false, message: 'Invalid phone number format' };
        }

        return { valid: true, message: '' };
    }

    /**
     * Validate URL
     * @param {string} value - URL to validate
     * @returns {Object} Validation result
     */
    function validateURL(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'URL is required' };
        }

        const trimmed = value.trim();

        if (!PATTERNS.url.test(trimmed)) {
            return { valid: false, message: 'Invalid URL format (must start with http:// or https://)' };
        }

        return { valid: true, message: '' };
    }

    /**
     * Validate port number
     * @param {string|number} value - Port to validate
     * @returns {Object} Validation result
     */
    function validatePort(value) {
        if (value === null || value === undefined || value === '') {
            return { valid: false, message: 'Port number is required' };
        }

        const strValue = String(value).trim();

        if (!PATTERNS.port.test(strValue)) {
            return { valid: false, message: 'Invalid port number (0-65535)' };
        }

        const port = parseInt(strValue, 10);
        if (port < 0 || port > 65535) {
            return { valid: false, message: 'Port number must be between 0 and 65535' };
        }

        return { valid: true, message: '' };
    }

    /**
     * Validate required field
     * @param {string} value - Value to validate
     * @returns {Object} Validation result
     */
    function validateRequired(value) {
        if (value === null || value === undefined || String(value).trim() === '') {
            return { valid: false, message: 'This field is required' };
        }

        return { valid: true, message: '' };
    }

    /**
     * Validate length constraints
     * @param {string} value - Value to validate
     * @param {number} min - Minimum length
     * @param {number} max - Maximum length
     * @returns {Object} Validation result
     */
    function validateLength(value, min = 0, max = Infinity) {
        const length = value ? String(value).length : 0;

        if (length < min) {
            return { valid: false, message: `Minimum length is ${min} characters` };
        }

        if (length > max) {
            return { valid: false, message: `Maximum length is ${max} characters` };
        }

        return { valid: true, message: '' };
    }

    /**
     * General pattern validator
     * @param {string} value - Value to validate
     * @param {string} type - Validation type
     * @returns {Object} Validation result
     */
    function validate(value, type) {
        switch (type) {
            case 'ip':
            case 'ipv4':
            case 'ipv6':
                return validateIP(value);
            case 'cidr':
                return validateCIDR(value);
            case 'domain':
                return validateDomain(value);
            case 'email':
                return validateEmail(value);
            case 'phone':
                return validatePhone(value);
            case 'url':
                return validateURL(value);
            case 'port':
                return validatePort(value);
            case 'required':
                return validateRequired(value);
            default:
                return { valid: true, message: '' };
        }
    }

    /**
     * Show validation feedback on input element
     * @param {HTMLElement} element - Input element
     * @param {Object} result - Validation result
     */
    function showFeedback(element, result) {
        // Remove existing feedback
        const existingFeedback = element.parentElement.querySelector('.validation-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }

        // Update input styling
        element.classList.remove('is-valid', 'is-invalid');

        if (result.valid) {
            element.classList.add('is-valid');
        } else {
            element.classList.add('is-invalid');

            // Add error message
            const feedback = document.createElement('div');
            feedback.className = 'validation-feedback invalid-feedback';
            feedback.textContent = result.message;
            feedback.style.display = 'block';
            feedback.style.color = '#dc3545';
            feedback.style.fontSize = '0.875em';
            feedback.style.marginTop = '0.25rem';

            element.parentElement.appendChild(feedback);
        }
    }

    /**
     * Attach real-time validator to input element
     * @param {HTMLElement} element - Input element
     * @param {string|Array} types - Validation type(s)
     * @param {Object} options - Validation options
     */
    function attachValidator(element, types, options = {}) {
        if (!(element instanceof HTMLElement)) {
            throw new Error('First argument must be an HTMLElement');
        }

        const typeArray = Array.isArray(types) ? types : [types];
        const debounceMs = options.debounce || 300;
        let timeoutId = null;

        const validateInput = function() {
            const value = element.value;
            let result = { valid: true, message: '' };

            // Run all validators
            for (const type of typeArray) {
                result = validate(value, type);
                if (!result.valid) {
                    break; // Stop at first error
                }
            }

            // Check length constraints
            if (result.valid && (options.minLength || options.maxLength)) {
                result = validateLength(value, options.minLength, options.maxLength);
            }

            // Show feedback
            if (options.showFeedback !== false) {
                showFeedback(element, result);
            }

            // Store validation result
            element.dataset.validationResult = result.valid ? 'valid' : 'invalid';

            // Call custom callback
            if (options.onValidate) {
                options.onValidate(result, element);
            }
        };

        // Debounced validation on input
        element.addEventListener('input', function() {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(validateInput, debounceMs);
        });

        // Immediate validation on blur
        element.addEventListener('blur', validateInput);

        // Initial validation if value exists
        if (element.value && options.validateOnLoad !== false) {
            validateInput();
        }
    }

    /**
     * Validate entire form
     * @param {HTMLFormElement} form - Form element to validate
     * @returns {boolean} True if form is valid
     */
    function validateForm(form) {
        if (!(form instanceof HTMLFormElement)) {
            throw new Error('Argument must be an HTMLFormElement');
        }

        let isValid = true;
        const inputs = form.querySelectorAll('input[data-validate], textarea[data-validate], select[data-validate]');

        inputs.forEach(input => {
            const validationType = input.dataset.validate;
            const value = input.value;

            let result = validate(value, validationType);

            // Check required
            if (input.hasAttribute('required')) {
                const requiredResult = validateRequired(value);
                if (!requiredResult.valid) {
                    result = requiredResult;
                }
            }

            // Check length
            if (input.hasAttribute('minlength') || input.hasAttribute('maxlength')) {
                const min = parseInt(input.getAttribute('minlength') || '0', 10);
                const max = parseInt(input.getAttribute('maxlength') || 'Infinity', 10);
                const lengthResult = validateLength(value, min, max);
                if (!lengthResult.valid) {
                    result = lengthResult;
                }
            }

            showFeedback(input, result);

            if (!result.valid) {
                isValid = false;
            }
        });

        return isValid;
    }

    /**
     * Prevent form submission if validation fails
     * @param {HTMLFormElement} form - Form element
     */
    function preventInvalidSubmission(form) {
        if (!(form instanceof HTMLFormElement)) {
            throw new Error('Argument must be an HTMLFormElement');
        }

        form.addEventListener('submit', function(event) {
            if (!validateForm(form)) {
                event.preventDefault();
                event.stopPropagation();

                // Focus first invalid input
                const firstInvalid = form.querySelector('.is-invalid');
                if (firstInvalid) {
                    firstInvalid.focus();
                }
            }
        });
    }

    // Public API
    return {
        // Validators
        validateIP,
        validateCIDR,
        validateDomain,
        validateEmail,
        validatePhone,
        validateURL,
        validatePort,
        validateRequired,
        validateLength,
        validate,

        // UI helpers
        showFeedback,
        attachValidator,
        validateForm,
        preventInvalidSubmission,

        // Patterns for custom use
        patterns: PATTERNS
    };
})();

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.InputValidator = InputValidator;
}
