/**
 * TSUNAMI v5.0 - Tema Sistemi
 * F-35 Kokpit Tema Yonetimi
 */

// Tema baslat
function initTheme() {
    const saved = localStorage.getItem('tsunami-theme') || 'cyan';
    document.documentElement.setAttribute('data-theme', saved);
    console.log('[TEMA] Yuklendi:', saved);
}

// Tema degistir
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('tsunami-theme', theme);
    console.log('[TEMA] Degistirildi:', theme);
}

// Tema toggle
function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'cyan';
    const newTheme = current === 'cyan' ? 'cockpit-bw' : 'cyan';
    setTheme(newTheme);
}

// Header tema butonu olustur
function createHeaderThemeToggle(container) {
    if (!container || container.querySelector('.theme-toggle-header')) return;

    const btn = document.createElement('button');
    btn.className = 'theme-toggle-header';
    btn.title = 'Tema Degistir (Ctrl+Shift+T)';
    btn.onclick = toggleTheme;
    btn.innerHTML = `
        <svg class="theme-icon-light" width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/>
        </svg>
        <svg class="theme-icon-dark" width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0 .39-.39.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96c.39-.39.39-1.03 0-1.41-.39-.39-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36c.39-.39.39-1.03 0-1.41-.39-.39-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>
        </svg>
    `;
    container.appendChild(btn);
}

// Floating tema butonu olustur
function createFloatingThemeToggle() {
    if (document.querySelector('.theme-toggle-float')) return;

    const btn = document.createElement('button');
    btn.className = 'theme-toggle-float';
    btn.title = 'Tema Degistir (Ctrl+Shift+T)';
    btn.onclick = toggleTheme;
    btn.innerHTML = `
        <svg class="icon-moon" viewBox="0 0 24 24"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/></svg>
        <svg class="icon-sun" viewBox="0 0 24 24"><path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0 .39-.39.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96c.39-.39.39-1.03 0-1.41-.39-.39-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36c.39-.39.39-1.03 0-1.41-.39-.39-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/></svg>
    `;
    document.body.appendChild(btn);
}

// Klavye kisayolu
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.shiftKey && e.key === 'T') {
        e.preventDefault();
        toggleTheme();
    }
});

// Sayfa yuklendiginde tema baslat
document.addEventListener('DOMContentLoaded', function() {
    initTheme();

    // Header varsa oraya, yoksa floating buton ekle
    const headerContainer = document.querySelector('.hud-status, .command-header .header-actions, .top-bar .btn-group');
    if (headerContainer) {
        createHeaderThemeToggle(headerContainer);
    } else {
        createFloatingThemeToggle();
    }
});

// Export
if (typeof window !== 'undefined') {
    window.initTheme = initTheme;
    window.setTheme = setTheme;
    window.toggleTheme = toggleTheme;
    window.createHeaderThemeToggle = createHeaderThemeToggle;
    window.createFloatingThemeToggle = createFloatingThemeToggle;
}
