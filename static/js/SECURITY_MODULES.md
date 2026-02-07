# TSUNAMI Frontend Security Modules

Production-ready JavaScript security modules for client-side protection.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Modules](#modules)
  - [XSS Protection](#xss-protection)
  - [Input Validator](#input-validator)
  - [Error Boundary](#error-boundary)
  - [Logger](#logger)
- [Usage Examples](#usage-examples)
- [Integration Guide](#integration-guide)
- [Security Best Practices](#security-best-practices)

---

## Overview

These modules provide comprehensive client-side security features:

- **XSS Protection**: DOMPurify-like sanitization and safe DOM manipulation
- **Input Validator**: Real-time validation for IP, domain, email, phone, etc.
- **Error Boundary**: Global error handling with user-friendly messages
- **Logger**: Structured logging with environment-aware behavior

All modules use IIFE pattern for encapsulation and work without external dependencies.

---

## Installation

### 1. Load Modules in HTML

Add these script tags to your HTML **before** any application code:

```html
<!-- Security Modules (order matters) -->
<script src="/static/js/utils/logger.js"></script>
<script src="/static/js/utils/error-boundary.js"></script>
<script src="/static/js/security/xss-protection.js"></script>
<script src="/static/js/security/input-validator.js"></script>

<!-- Main Application -->
<script src="/static/js/main.js"></script>

<!-- Your app-specific scripts -->
<script src="/static/js/app.js"></script>
```

### 2. Add CSP Nonce Meta Tag (Recommended)

```html
<meta property="csp-nonce" content="{{ csp_nonce }}">
```

Server-side (Flask example):
```python
import secrets

@app.context_processor
def inject_csp_nonce():
    return {'csp_nonce': secrets.token_urlsafe(16)}
```

---

## Modules

### XSS Protection

Prevents XSS attacks through HTML sanitization and safe DOM manipulation.

#### Key Features

- HTML sanitization (removes dangerous tags/attributes)
- Safe element creation
- Event delegation (no inline handlers)
- CSP nonce handling

#### API

```javascript
// Sanitize HTML string
const clean = XSSProtection.sanitize(userInput);
const cleanWithOptions = XSSProtection.sanitize(userInput, {
    allowedTags: ['p', 'strong', 'em'],
    allowedAttrs: ['class', 'id']
});

// Escape HTML (text only)
const escaped = XSSProtection.escapeHTML('<script>alert("xss")</script>');

// Create safe element
const div = XSSProtection.createSafeElement('div', {
    class: 'alert',
    id: 'message'
}, 'Safe text content');

// Safe content setting
XSSProtection.setSafeContent(element, userInput); // textContent
XSSProtection.setSafeHTML(element, userHTML);     // sanitized innerHTML

// Event delegation (instead of inline onclick)
XSSProtection.delegateEvent('.delete-btn', 'click', function(event) {
    event.preventDefault();
    const id = this.dataset.id;
    deleteItem(id);
});

// CSP nonce
const nonce = XSSProtection.getCSPNonce();
const script = XSSProtection.createSafeScript('/static/js/module.js');
```

#### Example: Safe User Content Display

```javascript
// BAD - Vulnerable to XSS
element.innerHTML = userComment;

// GOOD - Sanitized
XSSProtection.setSafeHTML(element, userComment);

// BETTER - Text only (no HTML)
XSSProtection.setSafeContent(element, userComment);
```

---

### Input Validator

Client-side validation with real-time feedback.

#### Supported Types

- `ip` - IPv4/IPv6 addresses
- `cidr` - CIDR notation (e.g., 192.168.1.0/24)
- `domain` - Domain names
- `email` - Email addresses
- `phone` - Phone numbers
- `url` - HTTP/HTTPS URLs
- `port` - Port numbers (0-65535)
- `required` - Non-empty validation

#### API

```javascript
// Validate single value
const result = InputValidator.validateIP('192.168.1.1');
// Returns: { valid: true, message: '' }

const result2 = InputValidator.validateEmail('invalid');
// Returns: { valid: false, message: 'Invalid email address format' }

// Attach real-time validator
InputValidator.attachValidator(inputElement, 'email', {
    showFeedback: true,
    debounce: 300,
    minLength: 5,
    maxLength: 100,
    onValidate: function(result, element) {
        console.log('Validation result:', result);
    }
});

// Validate entire form
const isValid = InputValidator.validateForm(formElement);

// Prevent invalid submission
InputValidator.preventInvalidSubmission(formElement);
```

#### Example: HTML Integration

```html
<!-- Auto-validation with data attributes -->
<form data-validate-form>
    <input
        type="text"
        data-validate="ip"
        data-min-length="7"
        placeholder="IP Address"
        required
    >

    <input
        type="email"
        data-validate="email"
        placeholder="Email"
    >

    <button type="submit">Submit</button>
</form>

<script>
// main.js automatically attaches validators to [data-validate] inputs
</script>
```

#### Example: Manual Validation

```javascript
function handleIPSubmit(event) {
    event.preventDefault();

    const ipInput = document.getElementById('ip-address');
    const result = InputValidator.validateIP(ipInput.value);

    if (!result.valid) {
        InputValidator.showFeedback(ipInput, result);
        return;
    }

    // Proceed with valid IP
    submitToServer(ipInput.value);
}
```

---

### Error Boundary

Global error handling with user-friendly messages (no stack traces to users).

#### Key Features

- Catches all JavaScript errors
- Catches unhandled promise rejections
- Network error handling
- Server error reporting
- User-friendly messages

#### API

```javascript
// Initialize (done in main.js)
ErrorBoundary.init({
    reportToServer: true,
    serverEndpoint: '/api/errors',
    showUserMessage: true,
    environment: 'production'
});

// Manually capture error
try {
    riskyOperation();
} catch (error) {
    ErrorBoundary.captureError({
        type: 'manual_error',
        message: error.message,
        stack: error.stack
    }, {
        context: 'user_action',
        userMessage: 'Failed to save changes. Please try again.'
    });
}

// Wrap function with error handling
const safeFunction = ErrorBoundary.wrap(riskyFunction, {
    context: 'data_processing'
});

// Get error stats
const stats = ErrorBoundary.getStats();
console.log(stats); // { total: 5, byType: {...}, recent: [...] }

// Show custom message
ErrorBoundary.showUserMessage('Your custom error message');
```

#### User Messages

Users see friendly messages instead of technical errors:

- Network errors: "Network connection issue. Please check your internet connection."
- Server errors (500): "Server error occurred. Our team has been notified."
- Not found (404): "The requested resource was not found."
- Unauthorized (401): "You are not authorized to perform this action."

#### Server-Side Error Endpoint

```python
# Flask example
@app.route('/api/errors', methods=['POST'])
def log_client_error():
    error_data = request.get_json()

    # Log to file/database
    app.logger.error(f"Client error: {error_data}")

    # Send to monitoring service (Sentry, etc.)
    # sentry_sdk.capture_message(error_data['message'])

    return '', 204
```

---

### Logger

Structured logging with production mode (removes console.log).

#### Key Features

- Log levels: DEBUG, INFO, WARN, ERROR
- Disabled console in production
- Log persistence (localStorage)
- Performance timing
- Export/download logs

#### API

```javascript
// Initialize (done in main.js)
Logger.init({
    level: 'info',
    enableConsole: true, // false in production
    environment: 'production',
    persistLogs: true
});

// Basic logging
Logger.debug('Debug info', { data: 'value' });
Logger.info('Information message');
Logger.warn('Warning message', { reason: 'low memory' });
Logger.error('Error occurred', errorObject);

// Specialized logging
Logger.logAPI('GET', '/api/users', {
    status: 200,
    duration: 145.3
});

Logger.logUserAction('button_click', {
    button: 'submit',
    form: 'login'
});

Logger.logPerformance('page_load', 2345.67, 'ms');

// Performance timing
const result = Logger.time('database_query', () => {
    return expensiveOperation();
});

// Async timing
await Logger.time('api_call', async () => {
    return await fetch('/api/data');
});

// Create namespaced logger
const moduleLogger = Logger.createLogger('MapModule');
moduleLogger.info('Map initialized'); // "[MapModule] Map initialized"

// Runtime control
Logger.setLevel('debug'); // Change log level
Logger.setConsole(true);  // Enable console output

// Log management
const logs = Logger.getLogs();
const errors = Logger.getLogsByLevel('ERROR');
const stats = Logger.getStats();
Logger.downloadLogs('tsunami-logs.json');
Logger.clearLogs();
```

#### Production vs Development

**Development:**
- All console methods work
- Logs shown in console
- Logs persisted to localStorage
- Level: DEBUG

**Production:**
- `console.log()`, `console.debug()`, `console.info()` disabled
- `console.warn()`, `console.error()` still work
- No console output
- Level: INFO

---

## Usage Examples

### Example 1: Safe Search Form

```html
<form id="ip-search" data-validate-form>
    <input
        type="text"
        id="ip-input"
        data-validate="ip"
        placeholder="Enter IP address"
        required
    >
    <button type="submit">Search</button>
    <div id="results"></div>
</form>

<script>
document.getElementById('ip-search').addEventListener('submit', function(e) {
    e.preventDefault();

    const ipInput = document.getElementById('ip-input');
    const ip = ipInput.value;

    // Log user action
    Logger.logUserAction('ip_search', { ip: ip });

    // Fetch results
    fetch(`/api/search?ip=${encodeURIComponent(ip)}`)
        .then(res => res.json())
        .then(data => {
            const resultsDiv = document.getElementById('results');

            // Safe HTML rendering
            const resultHTML = `<p>Found: ${data.count} results</p>`;
            XSSProtection.setSafeHTML(resultsDiv, resultHTML);
        })
        .catch(error => {
            Logger.error('Search failed', error);
        });
});
</script>
```

### Example 2: Dynamic Content with Event Delegation

```html
<div id="user-list"></div>

<script>
// Setup event delegation for delete buttons
XSSProtection.delegateEvent('[data-delete-user]', 'click', function(event) {
    event.preventDefault();
    const userId = this.dataset.deleteUser;

    Logger.logUserAction('delete_user', { userId: userId });

    if (confirm('Delete this user?')) {
        deleteUser(userId);
    }
});

// Render users safely
function renderUsers(users) {
    const container = document.getElementById('user-list');
    container.innerHTML = ''; // Clear

    users.forEach(user => {
        const userDiv = XSSProtection.createSafeElement('div', {
            class: 'user-card'
        });

        const nameSpan = XSSProtection.createSafeElement('span', {}, user.name);
        const deleteBtn = XSSProtection.createSafeElement('button', {
            'data-delete-user': user.id,
            class: 'btn-delete'
        }, 'Delete');

        userDiv.appendChild(nameSpan);
        userDiv.appendChild(deleteBtn);
        container.appendChild(userDiv);
    });
}
</script>
```

### Example 3: Multi-Field Form Validation

```html
<form id="contact-form" data-validate-form>
    <input
        type="text"
        data-validate="required"
        data-min-length="2"
        placeholder="Name"
    >

    <input
        type="email"
        data-validate="email"
        placeholder="Email"
    >

    <input
        type="tel"
        data-validate="phone"
        placeholder="Phone"
    >

    <input
        type="url"
        data-validate="url"
        placeholder="Website"
    >

    <button type="submit">Submit</button>
</form>

<script>
// Auto-validation is handled by main.js
// Just listen for submit
document.getElementById('contact-form').addEventListener('submit', function(e) {
    e.preventDefault();

    // Form already validated by InputValidator.preventInvalidSubmission
    const formData = new FormData(this);

    fetch('/api/contact', {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        ErrorBoundary.showUserMessage('Form submitted successfully!');
    });
});
</script>
```

---

## Integration Guide

### Step 1: Add HTML Meta Tags

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta property="csp-nonce" content="{{ csp_nonce }}">
    <title>TSUNAMI</title>
</head>
```

### Step 2: Load Security Modules

```html
<!-- Security modules (before app code) -->
<script src="/static/js/utils/logger.js"></script>
<script src="/static/js/utils/error-boundary.js"></script>
<script src="/static/js/security/xss-protection.js"></script>
<script src="/static/js/security/input-validator.js"></script>
<script src="/static/js/main.js"></script>

<!-- Your application code -->
<script src="/static/js/app.js"></script>
```

### Step 3: Use Data Attributes for Auto-Validation

```html
<form data-validate-form>
    <input data-validate="ip" placeholder="IP Address">
    <button type="submit">Submit</button>
</form>
```

### Step 4: Use Safe DOM Manipulation

```javascript
// Replace all innerHTML with safe alternatives
// element.innerHTML = userInput; // BAD
XSSProtection.setSafeContent(element, userInput); // GOOD
```

### Step 5: Wait for Initialization

```javascript
// Wait for app initialization
window.addEventListener('app:initialized', function(event) {
    console.log('App ready!', event.detail.config);

    // Your initialization code here
    initializeMap();
    loadInitialData();
});
```

---

## Security Best Practices

### 1. Never Trust User Input

```javascript
// Always validate
const result = InputValidator.validateIP(userInput);
if (!result.valid) {
    return; // Don't process
}

// Always sanitize
const clean = XSSProtection.sanitize(userInput);
```

### 2. Use Event Delegation

```javascript
// BAD - Inline handlers
<button onclick="deleteUser(123)">Delete</button>

// GOOD - Event delegation
<button data-action="delete" data-user-id="123">Delete</button>

XSSProtection.delegateEvent('[data-action="delete"]', 'click', handler);
```

### 3. Content Security Policy

Add CSP header on server:

```python
# Flask example
@app.after_request
def set_csp(response):
    nonce = g.csp_nonce
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: https:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none';"
    )
    return response
```

### 4. Error Handling

```javascript
// Don't expose technical details to users
try {
    riskyOperation();
} catch (error) {
    // Log technical details
    Logger.error('Operation failed', error);

    // Show user-friendly message
    ErrorBoundary.showUserMessage(
        'Unable to complete operation. Please try again.'
    );
}
```

### 5. Logging Best Practices

```javascript
// Don't log sensitive data
Logger.info('User logged in', {
    userId: user.id,  // OK
    // password: user.password  // NEVER!
});

// Use appropriate log levels
Logger.debug('Verbose info');      // Development only
Logger.info('Normal operation');    // Always logged
Logger.warn('Potential issue');     // Always logged
Logger.error('Error occurred');     // Always logged
```

---

## Browser Compatibility

- Modern browsers (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)
- ES6+ features used (const, let, arrow functions, template literals)
- No polyfills included (add if IE11 support needed)

---

## Performance Considerations

- **XSS Protection**: Sanitization adds ~5-10ms for typical user input
- **Input Validator**: Debounced validation (300ms default)
- **Logger**: Circular buffer prevents memory leaks
- **Error Boundary**: Non-blocking error reporting

---

## Troubleshooting

### Validators Not Working?

Check:
1. `data-validate` attribute present
2. `data-validate-form` on form element
3. main.js loaded and initialized

### CSP Blocking Scripts?

Check:
1. Nonce meta tag present
2. Scripts have nonce attribute
3. No inline event handlers (use delegation)

### Console.log Not Working?

Expected in production! Use:
```javascript
Logger.setConsole(true); // Temporary enable
```

---

## License

Part of TSUNAMI project - Internal use only.
