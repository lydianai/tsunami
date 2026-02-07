/**
 * TSUNAMI Theme Switcher
 * F-35 Cockpit Theme System
 *
 * Themes:
 * - cyan: Original cyan/blue theme
 * - cockpit-bw: Black & White F-35 Night Mode
 */

class TsunamiThemeManager {
    constructor() {
        this.currentTheme = localStorage.getItem('tsunami-theme') || 'cyan';
        this.themes = ['cyan', 'cockpit-bw'];
        this.init();
    }

    init() {
        // Apply saved theme
        this.applyTheme(this.currentTheme);

        // Create switcher UI
        this.createSwitcherUI();

        // Listen for system preference changes
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                // Optionally auto-switch based on system preference
                // this.applyTheme(e.matches ? 'cockpit-bw' : 'cyan');
            });
        }
    }

    applyTheme(themeName) {
        if (!this.themes.includes(themeName)) {
            console.warn(`Theme '${themeName}' not found, using default`);
            themeName = 'cyan';
        }

        document.documentElement.setAttribute('data-theme', themeName);
        this.currentTheme = themeName;
        localStorage.setItem('tsunami-theme', themeName);

        // Update active button
        document.querySelectorAll('.theme-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.theme === themeName);
        });

        // Dispatch event for other components
        window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: themeName } }));

        console.log(`[THEME] Switched to: ${themeName}`);
    }

    createSwitcherUI() {
        // Check if already exists
        if (document.querySelector('.theme-switcher')) return;

        const switcher = document.createElement('div');
        switcher.className = 'theme-switcher';
        switcher.innerHTML = `
            <button class="theme-btn ${this.currentTheme === 'cyan' ? 'active' : ''}"
                    data-theme="cyan"
                    title="Cyan Theme (Original)">
            </button>
            <button class="theme-btn ${this.currentTheme === 'cockpit-bw' ? 'active' : ''}"
                    data-theme="cockpit-bw"
                    title="Black & White Cockpit">
            </button>
        `;

        // Add click handlers
        switcher.querySelectorAll('.theme-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.applyTheme(btn.dataset.theme);
            });
        });

        document.body.appendChild(switcher);
    }

    // Toggle between themes
    toggle() {
        const currentIndex = this.themes.indexOf(this.currentTheme);
        const nextIndex = (currentIndex + 1) % this.themes.length;
        this.applyTheme(this.themes[nextIndex]);
    }

    // Get current theme
    getTheme() {
        return this.currentTheme;
    }

    // Reset to default
    reset() {
        this.applyTheme('cyan');
    }
}

// Initialize on DOM ready
let tsunamiTheme;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        tsunamiTheme = new TsunamiThemeManager();
    });
} else {
    tsunamiTheme = new TsunamiThemeManager();
}

// Keyboard shortcut: Ctrl+Shift+T to toggle theme
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && e.key === 'T') {
        e.preventDefault();
        if (tsunamiTheme) tsunamiTheme.toggle();
    }
});

// Export for global use
window.TsunamiTheme = {
    set: (theme) => tsunamiTheme?.applyTheme(theme),
    get: () => tsunamiTheme?.getTheme(),
    toggle: () => tsunamiTheme?.toggle(),
    reset: () => tsunamiTheme?.reset()
};
