#!/usr/bin/env python3
"""TSUNAMI Nirvana Dashboard - Aircraft Cockpit HUD Style
Production-Ready Version with Security Hardening
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Notify', '0.7')

from gi.repository import Gtk, Gdk, GLib, Gio, Notify, Pango
import json
import subprocess
import threading
import shlex
import logging
from datetime import datetime
from collections import deque
from pathlib import Path
from typing import Dict, List

import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("TSUNAMI")

# Configuration - Use environment variable or default
TSUNAMI_HOME = Path.home() / "Desktop" / "TSUNAMI"
if not TSUNAMI_HOME.exists():
    TSUNAMI_HOME = Path("/home/lydian/Desktop/TSUNAMI")
TSUNAMI_CONFIG = TSUNAMI_HOME / "tsunami_config.json"
APP_ID = "com.tsunami.nirvana.dashboard"

# Security: Allowed terminal commands whitelist
ALLOWED_COMMANDS = {
    "curl -s ifconfig.me",
    "systemctl status tor --no-pager | head -15",
    "ip -br addr",
    "ps aux --sort=-%cpu | head -15",
    "ss -tuln | head -20",
    "ss -tupn state established | head -15",
    "df -h",
    "free -h",
    "whoami && id && hostname",
    "last -10",
}

# Security: Commands that require sudo (prompt user)
SUDO_COMMANDS = {
    "sudo ufw status verbose",
    "sudo tail -20 /var/log/auth.log",
}

# Initialize notifications
Notify.init("TSUNAMI Nirvana")

# CSS - Aircraft Cockpit HUD Theme - RESPONSIVE
HUD_CSS = """
@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.6; }
    100% { opacity: 1; }
}

@keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
}

/* === BASE RESPONSIVE === */
window, .main-content {
    background-color: #000000;
}

headerbar {
    background-color: #0a0a0a;
    border-bottom: 1px solid #333333;
    min-height: 40px;
}
headerbar title {
    color: #ffffff;
    font-weight: 800;
    letter-spacing: 3px;
}

/* === RESPONSIVE CONTAINERS === */
.responsive-box {
    margin: 2px;
    padding: 4px;
}

.responsive-grid {
    margin: 4px;
}

/* === LEVEL BARS - RESPONSIVE === */
levelbar {
    min-height: 8px;
}
levelbar block.filled { background-color: #00ff00; }
levelbar block.empty { background-color: #1a1a1a; }
levelbar trough { background-color: #0a0a0a; min-height: 8px; }

.cpu-bar { min-height: 40px; }
.cpu-bar block.filled { background-color: #00ff00; min-width: 3px; }
.cpu-bar block.empty { background-color: #0a0a0a; }
.cpu-bar trough { background-color: #000000; min-width: 3px; }

.gauge-bar block.filled { background-color: #00ff00; }
.gauge-bar block.empty { background-color: #1a1a1a; }

.graph-area {
    background-color: #000000;
    border: 1px solid #1a1a1a;
    min-height: 50px;
}

/* === HUD PANELS - RESPONSIVE === */
.hud-panel {
    background-color: #000000;
    border: 1px solid #333333;
    border-radius: 0;
    padding: 8px;
    margin: 2px;
}
.hud-panel:hover { border-color: #00ff00; }

.panel-title {
    font-family: monospace;
    font-size: 10px;
    font-weight: 700;
    color: #00ff00;
    letter-spacing: 1px;
    margin-bottom: 6px;
    padding-bottom: 4px;
    border-bottom: 1px solid #1a1a1a;
}

/* === METRICS - SCALABLE === */
.metric-big {
    font-family: monospace;
    font-size: 24px;
    font-weight: 900;
    color: #ffffff;
}
.metric-medium {
    font-family: monospace;
    font-size: 18px;
    font-weight: 700;
    color: #ffffff;
}
.metric-label {
    font-family: monospace;
    font-size: 9px;
    color: #666666;
    letter-spacing: 1px;
}
.metric-unit {
    font-family: monospace;
    font-size: 10px;
    color: #888888;
}

.led-active {
    color: #00ff00;
    font-weight: 700;
}
.led-inactive {
    color: #ff0000;
    font-weight: 700;
}
.led-warning {
    color: #ffcc00;
    font-weight: 700;
    animation: pulse 1s infinite;
}

.status-badge {
    font-family: monospace;
    font-size: 10px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 0;
    letter-spacing: 1px;
}
.badge-aktif {
    background-color: #001a00;
    color: #00ff00;
    border: 1px solid #00ff00;
}
.badge-pasif {
    background-color: #1a0000;
    color: #ff0000;
    border: 1px solid #ff0000;
}
.badge-uyari {
    background-color: #1a1a00;
    color: #ffcc00;
    border: 1px solid #ffcc00;
}
.badge-kritik {
    background-color: #330000;
    color: #ff0000;
    border: 1px solid #ff0000;
}
.badge-yuksek {
    background-color: #331a00;
    color: #ff6600;
    border: 1px solid #ff6600;
}
.badge-orta {
    background-color: #333300;
    color: #ffcc00;
    border: 1px solid #ffcc00;
}
.badge-dusuk {
    background-color: #1a1a1a;
    color: #888888;
    border: 1px solid #666666;
}
.badge-bilgi {
    background-color: #001a1a;
    color: #00ffff;
    border: 1px solid #00ffff;
}

.threat-item {
    background-color: #0a0a0a;
    border-left: 3px solid #ff0000;
    padding: 8px 12px;
    margin: 4px 0;
}
.threat-critical { border-left-color: #ff0000; background-color: #1a0000; }
.threat-high { border-left-color: #ff6600; background-color: #1a0a00; }
.threat-medium { border-left-color: #ffcc00; background-color: #1a1a00; }
.threat-low { border-left-color: #888888; background-color: #0a0a0a; }
.threat-info { border-left-color: #00ffff; background-color: #001a1a; }

/* === BUTTONS - RESPONSIVE === */
.action-btn {
    background-color: #0a0a0a;
    border: 1px solid #00ff00;
    color: #00ff00;
    font-family: monospace;
    font-weight: 700;
    font-size: 9px;
    padding: 6px 10px;
    border-radius: 0;
    letter-spacing: 1px;
    min-height: 28px;
}
.action-btn:hover {
    background-color: #001a00;
    border-color: #00ff00;
}
.action-btn-danger {
    border-color: #ff0000;
    color: #ff0000;
}
.action-btn-danger:hover {
    background-color: #1a0000;
}

/* Small button variant */
.action-btn-small {
    font-size: 8px;
    padding: 4px 8px;
    min-height: 24px;
}

/* === TERMINAL - RESPONSIVE === */
.terminal-output {
    font-family: monospace;
    font-size: 10px;
    color: #00ff00;
    background-color: #000000;
    padding: 6px;
    border: 1px solid #1a1a1a;
}

.command-entry {
    font-family: monospace;
    font-size: 11px;
    color: #00ff00;
    background-color: #000000;
    border: 1px solid #333333;
    padding: 6px 10px;
    min-height: 30px;
}
.command-entry:focus {
    border-color: #00ff00;
}

/* === NOTEBOOK TABS - RESPONSIVE === */
notebook > header {
    background-color: #000000;
    border-bottom: 1px solid #333333;
    min-height: 32px;
}
notebook > header > tabs > tab {
    font-family: monospace;
    font-size: 9px;
    background-color: transparent;
    color: #666666;
    padding: 6px 12px;
    letter-spacing: 1px;
    border-bottom: 2px solid transparent;
}
notebook > header > tabs > tab:hover { color: #ffffff; background-color: #0a0a0a; }
notebook > header > tabs > tab:checked {
    color: #00ff00;
    border-bottom-color: #00ff00;
    background-color: #0a0a0a;
}

/* === SCROLLBAR - COMPACT === */
scrollbar { background-color: #000000; }
scrollbar slider { background-color: #333333; min-width: 4px; min-height: 20px; }
scrollbar slider:hover { background-color: #00ff00; }

/* === STATUS BAR - RESPONSIVE === */
.status-bar {
    background-color: #000000;
    border-top: 1px solid #333333;
    padding: 4px 8px;
    font-family: monospace;
    font-size: 9px;
    color: #666666;
    min-height: 20px;
}

/* === MODULE ROW - COMPACT === */
.module-row {
    padding: 4px 8px;
    border-bottom: 1px solid #1a1a1a;
    min-height: 28px;
}
.module-row:hover { background-color: #0a0a0a; }
.module-name {
    font-family: monospace;
    font-size: 10px;
    color: #ffffff;
}

/* === GAUGE COLORS === */
.gauge-bg { background-color: #1a1a1a; }
.gauge-fill { background-color: #00ff00; }
.gauge-warning { background-color: #ffcc00; }
.gauge-critical { background-color: #ff0000; }

/* === SETTINGS - RESPONSIVE === */
.settings-group {
    background-color: #0a0a0a;
    border: 1px solid #333333;
    padding: 10px;
    margin: 4px;
}
.settings-title {
    font-family: monospace;
    font-size: 10px;
    font-weight: 700;
    color: #00ff00;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

/* === FORM ELEMENTS === */
switch { background-color: #1a1a1a; border-radius: 0; min-width: 40px; }
switch:checked { background-color: #00ff00; }
switch slider { background-color: #333333; border-radius: 0; }

entry {
    font-family: monospace;
    font-size: 10px;
    background-color: #000000;
    border: 1px solid #333333;
    color: #ffffff;
    min-height: 28px;
    padding: 4px 8px;
}
entry:focus { border-color: #00ff00; }

/* === RESPONSIVE UTILITIES === */
.compact { padding: 2px 4px; margin: 1px; }
.expand-h { min-width: 100px; }
.expand-v { min-height: 50px; }

/* === FLOWBOX - RESPONSIVE GRID === */
flowbox { background-color: transparent; }
flowboxchild { background-color: transparent; padding: 2px; }
"""


class CPUGraph(Gtk.Box):
    """CPU usage history graph using bars"""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=1)
        self.history = deque(maxlen=30)
        self.bars = []
        self.set_size_request(200, 60)
        self.add_css_class("graph-area")

        # Create 30 vertical bars
        for i in range(30):
            bar = Gtk.LevelBar()
            bar.set_orientation(Gtk.Orientation.VERTICAL)
            bar.set_min_value(0)
            bar.set_max_value(100)
            bar.set_value(0)
            bar.set_hexpand(False)
            bar.set_vexpand(True)
            bar.add_css_class("cpu-bar")
            self.bars.append(bar)
            self.append(bar)

    def add_value(self, value: float):
        self.history.append(value)
        # Update bars from history
        history_list = list(self.history)
        for i, bar in enumerate(self.bars):
            if i < len(history_list):
                bar.set_value(history_list[i])
            else:
                bar.set_value(0)


class GaugeWidget(Gtk.Box):
    """Circular gauge widget using GTK widgets"""

    def __init__(self, label: str = ""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._value = 0
        self.set_size_request(100, 100)
        self.set_halign(Gtk.Align.CENTER)

        # Value display
        self.value_label = Gtk.Label(label="0%")
        self.value_label.add_css_class("metric-big")
        self.append(self.value_label)

        # Progress bar as gauge
        self.progress = Gtk.LevelBar()
        self.progress.set_min_value(0)
        self.progress.set_max_value(100)
        self.progress.set_value(0)
        self.progress.set_size_request(80, 12)
        self.progress.add_css_class("gauge-bar")
        self.append(self.progress)

        # Label
        label_widget = Gtk.Label(label=label)
        label_widget.add_css_class("metric-label")
        self.append(label_widget)

    def set_value(self, value: float):
        self._value = max(0, min(100, value))
        self.value_label.set_text(f"{int(self._value)}%")
        self.progress.set_value(self._value)

        # Color based on value
        self.value_label.remove_css_class("led-active")
        self.value_label.remove_css_class("led-warning")
        self.value_label.remove_css_class("led-inactive")

        if self._value > 80:
            self.value_label.add_css_class("led-inactive")  # Red
        elif self._value > 60:
            self.value_label.add_css_class("led-warning")  # Amber
        else:
            self.value_label.add_css_class("led-active")  # Green


class TsunamiNirvanaDashboard(Gtk.Application):
    """Main dashboard application"""

    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.window = None
        self.cpu_graph = None
        self.ram_gauge = None
        self.disk_gauge = None
        self.module_widgets = {}
        self.threat_list = None
        self.event_list = None
        self.net_in_label = None
        self.net_out_label = None
        self.conn_count_label = None
        self.cpu_label = None
        self.ram_label = None
        self.disk_label = None
        self.status_label = None
        self.terminal_buffer = None
        self.last_net_io = psutil.net_io_counters()
        self.last_net_time = datetime.now()
        self.threats = deque(maxlen=50)
        self.events = deque(maxlen=100)
        self.notification_history = []
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load configuration with proper error handling"""
        default_config = {
            "stealth": {"ghost_mode": False},
            "settings": {
                "desktop_notifications": True,
                "sound_alerts": False,
                "network_monitoring": True,
                "process_monitoring": True
            }
        }
        try:
            if not TSUNAMI_CONFIG.exists():
                logger.info(f"Config file not found, using defaults: {TSUNAMI_CONFIG}")
                return default_config

            with open(TSUNAMI_CONFIG, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info(f"Config loaded from: {TSUNAMI_CONFIG}")
                return config
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return default_config
        except PermissionError:
            logger.error(f"Permission denied reading config: {TSUNAMI_CONFIG}")
            return default_config
        except Exception as e:
            logger.error(f"Config load error: {e}")
            return default_config

    def _save_config(self):
        """Save configuration with proper error handling"""
        try:
            # Ensure parent directory exists
            TSUNAMI_CONFIG.parent.mkdir(parents=True, exist_ok=True)

            with open(TSUNAMI_CONFIG, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            logger.info("Config saved successfully")
        except PermissionError:
            error_msg = f"Config kayit hatasi: Yazma izni yok"
            logger.error(error_msg)
            if hasattr(self, '_log_event'):
                self._log_event(error_msg, "error")
        except Exception as e:
            error_msg = f"Config kayit hatasi: {e}"
            logger.error(error_msg)
            if hasattr(self, '_log_event'):
                self._log_event(error_msg, "error")

    def do_activate(self):
        if self.window:
            self.window.present()
            return

        # Apply CSS
        css_provider = Gtk.CssProvider()
        css_provider.load_from_data(HUD_CSS.encode())
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        # Main window - RESPONSIVE
        self.window = Gtk.ApplicationWindow(application=self)
        self.window.set_title("TSUNAMI NIRVANA")
        self.window.set_default_size(1000, 700)
        self.window.set_decorated(True)
        self.window.set_resizable(True)

        # Set WM class for dock integration
        self.window.set_startup_id(APP_ID)

        # Connect to size change for responsive adjustments
        self.window.connect("notify::default-width", self._on_window_resize)
        self.window.connect("notify::default-height", self._on_window_resize)

        # HeaderBar with controls - COMPACT
        header = Gtk.HeaderBar()
        header.set_show_title_buttons(True)

        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title_label = Gtk.Label(label="TSUNAMI")
        title_label.add_css_class("main-title")
        title_box.append(title_label)
        header.set_title_widget(title_box)

        self.window.set_titlebar(header)

        # Main layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_box.add_css_class("main-content")

        # Notebook for tabs
        notebook = Gtk.Notebook()
        notebook.set_tab_pos(Gtk.PositionType.TOP)

        # Tab 1: Genel Bakis
        notebook.append_page(self._create_overview_tab(), Gtk.Label(label="GENEL BAKIS"))

        # Tab 2: Tehditler
        notebook.append_page(self._create_threats_tab(), Gtk.Label(label="TEHDITLER"))

        # Tab 3: Ag Izleme
        notebook.append_page(self._create_network_tab(), Gtk.Label(label="AG IZLEME"))

        # Tab 4: Olaylar
        notebook.append_page(self._create_events_tab(), Gtk.Label(label="OLAYLAR"))

        # Tab 5: Hizli Komut
        notebook.append_page(self._create_command_tab(), Gtk.Label(label="HIZLI KOMUT"))

        # Tab 6: Ayarlar
        notebook.append_page(self._create_settings_tab(), Gtk.Label(label="AYARLAR"))

        main_box.append(notebook)

        # Status bar
        self.status_label = Gtk.Label(label="SISTEM AKTIF | Son guncelleme: --:--:--")
        self.status_label.add_css_class("status-bar")
        self.status_label.set_halign(Gtk.Align.START)
        main_box.append(self.status_label)

        self.window.set_child(main_box)

        # Start refresh timer
        GLib.timeout_add(1000, self._refresh_data)

        # Initial data load - delayed to ensure widgets are ready
        GLib.timeout_add(500, self._initial_load)

        # Initial data load
        self._refresh_data()

        self.window.present()

    def _create_overview_tab(self) -> Gtk.Widget:
        """Create overview tab with system metrics and module status - RESPONSIVE"""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        main_box.set_margin_start(4)
        main_box.set_margin_end(4)
        main_box.set_margin_top(4)
        main_box.set_margin_bottom(4)
        main_box.set_hexpand(True)
        main_box.set_vexpand(True)

        # Top row: System metrics - RESPONSIVE using FlowBox
        metrics_flow = Gtk.FlowBox()
        metrics_flow.set_selection_mode(Gtk.SelectionMode.NONE)
        metrics_flow.set_homogeneous(True)
        metrics_flow.set_min_children_per_line(2)
        metrics_flow.set_max_children_per_line(4)
        metrics_flow.set_row_spacing(4)
        metrics_flow.set_column_spacing(4)

        # CPU Panel
        cpu_panel = self._create_panel("CPU")
        cpu_panel.set_hexpand(True)
        cpu_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        cpu_content.set_hexpand(True)

        self.cpu_label = Gtk.Label(label="0%")
        self.cpu_label.add_css_class("metric-big")
        cpu_content.append(self.cpu_label)

        self.cpu_graph = CPUGraph()
        self.cpu_graph.set_hexpand(True)
        cpu_content.append(self.cpu_graph)

        cpu_panel.append(cpu_content)
        metrics_flow.append(cpu_panel)

        # RAM Panel
        ram_panel = self._create_panel("RAM")
        ram_panel.set_hexpand(True)
        ram_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        ram_content.set_halign(Gtk.Align.CENTER)
        ram_content.set_hexpand(True)

        self.ram_gauge = GaugeWidget("RAM")
        ram_content.append(self.ram_gauge)

        self.ram_label = Gtk.Label(label="0 / 0 GB")
        self.ram_label.add_css_class("metric-label")
        ram_content.append(self.ram_label)

        ram_panel.append(ram_content)
        metrics_flow.append(ram_panel)

        # Disk Panel
        disk_panel = self._create_panel("DISK")
        disk_panel.set_hexpand(True)
        disk_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        disk_content.set_halign(Gtk.Align.CENTER)
        disk_content.set_hexpand(True)

        self.disk_gauge = GaugeWidget("DISK")
        disk_content.append(self.disk_gauge)

        self.disk_label = Gtk.Label(label="0 / 0 GB")
        self.disk_label.add_css_class("metric-label")
        disk_content.append(self.disk_label)

        disk_panel.append(disk_content)
        metrics_flow.append(disk_panel)

        # Network Panel
        net_panel = self._create_panel("AG")
        net_panel.set_hexpand(True)
        net_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        net_content.set_hexpand(True)

        # Network In
        net_in_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        net_in_icon = Gtk.Label(label="↓")
        net_in_icon.add_css_class("led-active")
        self.net_in_label = Gtk.Label(label="0 KB/s")
        self.net_in_label.add_css_class("metric-medium")
        net_in_box.append(net_in_icon)
        net_in_box.append(self.net_in_label)
        net_content.append(net_in_box)

        # Network Out
        net_out_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        net_out_icon = Gtk.Label(label="↑")
        net_out_icon.add_css_class("led-warning")
        self.net_out_label = Gtk.Label(label="0 KB/s")
        self.net_out_label.add_css_class("metric-medium")
        net_out_box.append(net_out_icon)
        net_out_box.append(self.net_out_label)
        net_content.append(net_out_box)

        # Connections
        conn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        conn_icon = Gtk.Label(label="⚡")
        conn_icon.add_css_class("metric-label")
        self.conn_count_label = Gtk.Label(label="0")
        self.conn_count_label.add_css_class("metric-medium")
        conn_box.append(conn_icon)
        conn_box.append(self.conn_count_label)
        net_content.append(conn_box)

        net_panel.append(net_content)
        metrics_flow.append(net_panel)

        main_box.append(metrics_flow)

        # Middle row: Module status and Quick actions - RESPONSIVE
        middle_flow = Gtk.FlowBox()
        middle_flow.set_selection_mode(Gtk.SelectionMode.NONE)
        middle_flow.set_homogeneous(False)
        middle_flow.set_min_children_per_line(1)
        middle_flow.set_max_children_per_line(2)
        middle_flow.set_row_spacing(4)
        middle_flow.set_column_spacing(4)

        # Module Status Panel
        module_panel = self._create_panel("MODULLER")
        module_panel.set_hexpand(True)
        module_panel.set_vexpand(False)

        module_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)

        modules = [
            ("BEYIN", "pgrep -f dalga_web.py"),
            ("Guardian", "pgrep -f network_guardian.py"),
            ("Defender", "pgrep -f tsunami_defender.py"),
            ("TOR", "systemctl is-active tor"),
            ("Ghost", "config:stealth.ghost_mode"),
        ]

        for name, check_cmd in modules:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.add_css_class("module-row")

            name_label = Gtk.Label(label=name)
            name_label.add_css_class("module-name")
            name_label.set_halign(Gtk.Align.START)
            name_label.set_hexpand(True)
            row.append(name_label)

            status_label = Gtk.Label(label="...")
            status_label.add_css_class("status-badge")
            status_label.add_css_class("badge-uyari")
            row.append(status_label)

            self.module_widgets[name] = {
                "label": status_label,
                "check": check_cmd
            }

            module_list.append(row)

        module_panel.append(module_list)
        middle_flow.append(module_panel)

        # Quick Actions Panel - COMPACT
        actions_panel = self._create_panel("AKSIYONLAR")
        actions_panel.set_hexpand(True)

        actions_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)

        # TOR Yenile
        tor_btn = Gtk.Button(label="TOR YENILE")
        tor_btn.add_css_class("action-btn")
        tor_btn.add_css_class("action-btn-small")
        tor_btn.connect("clicked", self._on_tor_new_identity)
        actions_box.append(tor_btn)

        # Ghost Mode Toggle
        ghost_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ghost_label = Gtk.Label(label="GHOST")
        ghost_label.add_css_class("module-name")
        ghost_label.set_hexpand(True)
        ghost_box.append(ghost_label)

        self.ghost_switch = Gtk.Switch()
        self.ghost_switch.set_active(self.config.get("stealth", {}).get("ghost_mode", False))
        self.ghost_switch.connect("state-set", self._on_ghost_toggle)
        ghost_box.append(self.ghost_switch)
        actions_box.append(ghost_box)

        # Acil Tarama
        scan_btn = Gtk.Button(label="TARA")
        scan_btn.add_css_class("action-btn")
        scan_btn.add_css_class("action-btn-small")
        scan_btn.add_css_class("action-btn-danger")
        scan_btn.connect("clicked", self._on_emergency_scan)
        actions_box.append(scan_btn)

        # Sistem Guncelle
        update_btn = Gtk.Button(label="YENILE")
        update_btn.add_css_class("action-btn")
        update_btn.add_css_class("action-btn-small")
        update_btn.connect("clicked", lambda _: self._refresh_data())
        actions_box.append(update_btn)

        actions_panel.append(actions_box)
        middle_flow.append(actions_panel)

        main_box.append(middle_flow)

        # Bottom: Recent threats - RESPONSIVE
        threat_panel = self._create_panel("SON TEHDITLER")
        threat_panel.set_vexpand(True)
        threat_panel.set_hexpand(True)

        threat_scroll = Gtk.ScrolledWindow()
        threat_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        threat_scroll.set_vexpand(True)
        threat_scroll.set_hexpand(True)

        self.threat_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.threat_list.set_hexpand(True)
        threat_scroll.set_child(self.threat_list)

        # Add sample initial message
        self._add_threat_item("SISTEM", "Dashboard baslatildi", "info")

        threat_panel.append(threat_scroll)
        main_box.append(threat_panel)

        scroll.set_child(main_box)
        return scroll

    def _create_threats_tab(self) -> Gtk.Widget:
        """Create threats tab"""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(8)
        box.set_margin_end(8)
        box.set_margin_top(8)
        box.set_margin_bottom(8)

        # Header
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        title = Gtk.Label(label="TEHDIT IZLEME MERKEZI")
        title.add_css_class("panel-title")
        title.set_halign(Gtk.Align.START)
        title.set_hexpand(True)
        header.append(title)

        # Threat count label
        self.threat_count_label = Gtk.Label(label="0 Tehdit")
        self.threat_count_label.add_css_class("led-active")
        header.append(self.threat_count_label)

        # Scan button
        scan_btn = Gtk.Button(label="TARA")
        scan_btn.add_css_class("action-btn")
        scan_btn.connect("clicked", lambda _: self._manual_threat_scan())
        header.append(scan_btn)

        # Filter buttons
        all_btn = Gtk.Button(label="TUMU")
        all_btn.add_css_class("action-btn")
        all_btn.connect("clicked", lambda _: self._filter_threats("all"))
        header.append(all_btn)

        critical_btn = Gtk.Button(label="KRITIK")
        critical_btn.add_css_class("action-btn")
        critical_btn.add_css_class("action-btn-danger")
        critical_btn.connect("clicked", lambda _: self._filter_threats("critical"))
        header.append(critical_btn)

        box.append(header)

        # Status panel
        status_panel = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        status_panel.add_css_class("hud-panel")
        status_panel.set_margin_bottom(8)

        # Threat stats
        stats = [
            ("KRITIK", "threat_critical_count", "led-inactive"),
            ("YUKSEK", "threat_high_count", "led-warning"),
            ("ORTA", "threat_medium_count", "led-warning"),
            ("DUSUK", "threat_low_count", "led-active"),
        ]

        for label_text, attr_name, css_class in stats:
            stat_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            stat_box.set_halign(Gtk.Align.CENTER)

            count_label = Gtk.Label(label="0")
            count_label.add_css_class("metric-big")
            count_label.add_css_class(css_class)
            setattr(self, attr_name, count_label)
            stat_box.append(count_label)

            name_label = Gtk.Label(label=label_text)
            name_label.add_css_class("metric-label")
            stat_box.append(name_label)

            status_panel.append(stat_box)

        # Last scan time
        scan_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        scan_info.set_hexpand(True)
        scan_info.set_halign(Gtk.Align.END)

        self.last_scan_label = Gtk.Label(label="Son tarama: --:--:--")
        self.last_scan_label.add_css_class("metric-label")
        scan_info.append(self.last_scan_label)

        self.scan_status_label = Gtk.Label(label="Bekleniyor...")
        self.scan_status_label.add_css_class("led-warning")
        scan_info.append(self.scan_status_label)

        status_panel.append(scan_info)
        box.append(status_panel)

        # Threat list
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)

        self.full_threat_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        scroll.set_child(self.full_threat_list)

        box.append(scroll)

        return box

    def _manual_threat_scan(self):
        """Manual threat scan triggered by user"""
        self.scan_status_label.set_text("Taraniyor...")
        self.scan_status_label.remove_css_class("led-active")
        self.scan_status_label.add_css_class("led-warning")

        def do_scan():
            GLib.idle_add(self._refresh_threats_tab)
            GLib.idle_add(self._update_scan_status)

        threading.Thread(target=do_scan, daemon=True).start()

    def _update_scan_status(self):
        """Update scan status after completion"""
        self.last_scan_label.set_text(f"Son tarama: {datetime.now().strftime('%H:%M:%S')}")
        self.scan_status_label.set_text("Tamamlandi")
        self.scan_status_label.remove_css_class("led-warning")
        self.scan_status_label.add_css_class("led-active")

    def _filter_threats(self, filter_type: str):
        """Filter threats by type"""
        # For now just refresh - can be extended
        self._refresh_threats_tab()

    def _create_network_tab(self) -> Gtk.Widget:
        """Create network monitoring tab"""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(8)
        box.set_margin_end(8)
        box.set_margin_top(8)
        box.set_margin_bottom(8)

        # Network stats
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        stats_box.set_homogeneous(True)

        # Active connections
        conn_panel = self._create_panel("AKTIF BAGLANTILAR")
        self.net_conn_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(self.net_conn_list)
        scroll.set_vexpand(True)

        conn_panel.append(scroll)
        stats_box.append(conn_panel)

        # Interface stats
        iface_panel = self._create_panel("ARAYUZ ISTATISTIKLERI")
        self.iface_stats = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        iface_panel.append(self.iface_stats)
        stats_box.append(iface_panel)

        box.append(stats_box)

        return box

    def _create_events_tab(self) -> Gtk.Widget:
        """Create events tab"""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(8)
        box.set_margin_end(8)
        box.set_margin_top(8)
        box.set_margin_bottom(8)

        # Header
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        title = Gtk.Label(label="SISTEM OLAYLARI")
        title.add_css_class("panel-title")
        title.set_halign(Gtk.Align.START)
        title.set_hexpand(True)
        header.append(title)

        clear_btn = Gtk.Button(label="TEMIZLE")
        clear_btn.add_css_class("action-btn")
        clear_btn.connect("clicked", self._clear_events)
        header.append(clear_btn)

        box.append(header)

        # Events list
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)

        self.event_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        scroll.set_child(self.event_list)

        box.append(scroll)

        return box

    def _create_command_tab(self) -> Gtk.Widget:
        """Create quick command tab"""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(8)
        box.set_margin_end(8)
        box.set_margin_top(8)
        box.set_margin_bottom(8)

        # Terminal output
        output_panel = self._create_panel("TERMINAL CIKISI")
        output_panel.set_vexpand(True)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)

        self.terminal_view = Gtk.TextView()
        self.terminal_view.set_editable(False)
        self.terminal_view.set_monospace(True)
        self.terminal_view.add_css_class("terminal-output")
        self.terminal_buffer = self.terminal_view.get_buffer()
        self.terminal_buffer.set_text("TSUNAMI Terminal Ready\n> ")
        scroll.set_child(self.terminal_view)

        output_panel.append(scroll)
        box.append(output_panel)

        # Command input
        input_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        prompt = Gtk.Label(label=">")
        prompt.add_css_class("led-active")
        input_box.append(prompt)

        self.cmd_entry = Gtk.Entry()
        self.cmd_entry.set_placeholder_text("Komut girin...")
        self.cmd_entry.add_css_class("command-entry")
        self.cmd_entry.set_hexpand(True)
        self.cmd_entry.connect("activate", self._on_command_execute)
        input_box.append(self.cmd_entry)

        run_btn = Gtk.Button(label="CALISTIR")
        run_btn.add_css_class("action-btn")
        run_btn.connect("clicked", self._on_command_execute)
        input_box.append(run_btn)

        box.append(input_box)

        # Quick command buttons - Row 1
        quick_box1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        quick_commands1 = [
            ("IP GOSTER", "curl -s ifconfig.me"),
            ("TOR DURUMU", "systemctl status tor --no-pager | head -15"),
            ("AG DURUMU", "ip -br addr"),
            ("SURECLER", "ps aux --sort=-%cpu | head -15"),
        ]

        for label, cmd in quick_commands1:
            btn = Gtk.Button(label=label)
            btn.add_css_class("action-btn")
            btn.connect("clicked", lambda _, c=cmd: self._run_terminal_command(c))
            quick_box1.append(btn)

        box.append(quick_box1)

        # Quick command buttons - Row 2
        quick_box2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        quick_commands2 = [
            ("PORTLAR", "ss -tuln | head -20"),
            ("BAGLANTILAR", "ss -tupn state established | head -15"),
            ("DISK", "df -h"),
            ("BELLEK", "free -h"),
        ]

        for label, cmd in quick_commands2:
            btn = Gtk.Button(label=label)
            btn.add_css_class("action-btn")
            btn.connect("clicked", lambda _, c=cmd: self._run_terminal_command(c))
            quick_box2.append(btn)

        box.append(quick_box2)

        # Quick command buttons - Row 3 (Security)
        quick_box3 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        quick_commands3 = [
            ("UFW DURUM", "sudo ufw status verbose"),
            ("SON GIRIS", "last -10"),
            ("AUTH LOG", "sudo tail -20 /var/log/auth.log"),
            ("WHOAMI", "whoami && id && hostname"),
        ]

        for label, cmd in quick_commands3:
            btn = Gtk.Button(label=label)
            btn.add_css_class("action-btn")
            btn.add_css_class("action-btn-danger")
            btn.connect("clicked", lambda _, c=cmd: self._run_terminal_command(c))
            quick_box3.append(btn)

        box.append(quick_box3)

        return box

    def _create_settings_tab(self) -> Gtk.Widget:
        """Create settings tab with real working settings"""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_start(16)
        box.set_margin_end(16)
        box.set_margin_top(16)
        box.set_margin_bottom(16)

        # Initialize settings if not exist
        if "settings" not in self.config:
            self.config["settings"] = {
                "ghost_mode": False,
                "auto_tor": False,
                "network_monitoring": True,
                "process_monitoring": True,
                "desktop_notifications": True,
                "sound_alerts": False
            }
            self._save_config()

        settings = self.config.get("settings", {})

        # Stealth Settings
        stealth_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        stealth_group.add_css_class("settings-group")

        stealth_title = Gtk.Label(label="GIZLILIK AYARLARI")
        stealth_title.add_css_class("settings-title")
        stealth_title.set_halign(Gtk.Align.START)
        stealth_group.append(stealth_title)

        # Ghost Mode
        ghost_row = self._create_setting_row(
            "Ghost Mode", "Tam gizlilik modu - tum izler silinir",
            settings.get("ghost_mode", False), "ghost_mode"
        )
        stealth_group.append(ghost_row)

        # Auto TOR
        auto_tor_row = self._create_setting_row(
            "Otomatik TOR", "Dashboard acildiginda TOR baslatilir",
            settings.get("auto_tor", False), "auto_tor"
        )
        stealth_group.append(auto_tor_row)

        box.append(stealth_group)

        # Monitoring Settings
        monitor_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        monitor_group.add_css_class("settings-group")

        monitor_title = Gtk.Label(label="IZLEME AYARLARI")
        monitor_title.add_css_class("settings-title")
        monitor_title.set_halign(Gtk.Align.START)
        monitor_group.append(monitor_title)

        # Network monitoring
        net_mon_row = self._create_setting_row(
            "Ag Izleme", "Aktif baglantilari ve portlari izle",
            settings.get("network_monitoring", True), "network_monitoring"
        )
        monitor_group.append(net_mon_row)

        # Process monitoring
        proc_mon_row = self._create_setting_row(
            "Surec Izleme", "Yuksek CPU/RAM kullanan surecleri izle",
            settings.get("process_monitoring", True), "process_monitoring"
        )
        monitor_group.append(proc_mon_row)

        box.append(monitor_group)

        # Notification Settings
        notif_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        notif_group.add_css_class("settings-group")

        notif_title = Gtk.Label(label="BILDIRIM AYARLARI")
        notif_title.add_css_class("settings-title")
        notif_title.set_halign(Gtk.Align.START)
        notif_group.append(notif_title)

        # Desktop notifications
        desktop_notif_row = self._create_setting_row(
            "Masaustu Bildirimi", "Tehdit tespit edildiginde bildirim goster",
            settings.get("desktop_notifications", True), "desktop_notifications"
        )
        notif_group.append(desktop_notif_row)

        # Sound alerts
        sound_row = self._create_setting_row(
            "Ses Uyarilari", "Kritik tehditlerde ses cal",
            settings.get("sound_alerts", False), "sound_alerts"
        )
        notif_group.append(sound_row)

        box.append(notif_group)

        # Service Control Section
        service_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        service_group.add_css_class("settings-group")

        service_title = Gtk.Label(label="SERVIS KONTROL")
        service_title.add_css_class("settings-title")
        service_title.set_halign(Gtk.Align.START)
        service_group.append(service_title)

        # Service buttons
        service_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        start_beyin_btn = Gtk.Button(label="BEYIN BASLAT")
        start_beyin_btn.add_css_class("action-btn")
        start_beyin_btn.connect("clicked", lambda _: self._start_service("dalga_web.py"))
        service_buttons.append(start_beyin_btn)

        start_guardian_btn = Gtk.Button(label="GUARDIAN BASLAT")
        start_guardian_btn.add_css_class("action-btn")
        start_guardian_btn.connect("clicked", lambda _: self._start_service("network_guardian.py"))
        service_buttons.append(start_guardian_btn)

        start_defender_btn = Gtk.Button(label="DEFENDER BASLAT")
        start_defender_btn.add_css_class("action-btn")
        start_defender_btn.connect("clicked", lambda _: self._start_service("tsunami_defender.py"))
        service_buttons.append(start_defender_btn)

        service_group.append(service_buttons)

        # TOR control
        tor_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        start_tor_btn = Gtk.Button(label="TOR BASLAT")
        start_tor_btn.add_css_class("action-btn")
        start_tor_btn.connect("clicked", lambda _: self._control_tor("start"))
        tor_buttons.append(start_tor_btn)

        stop_tor_btn = Gtk.Button(label="TOR DURDUR")
        stop_tor_btn.add_css_class("action-btn")
        stop_tor_btn.add_css_class("action-btn-danger")
        stop_tor_btn.connect("clicked", lambda _: self._control_tor("stop"))
        tor_buttons.append(stop_tor_btn)

        service_group.append(tor_buttons)
        box.append(service_group)

        # System Info Section
        info_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        info_group.add_css_class("settings-group")

        info_title = Gtk.Label(label="SISTEM BILGISI")
        info_title.add_css_class("settings-title")
        info_title.set_halign(Gtk.Align.START)
        info_group.append(info_title)

        # System info
        import platform
        sys_info = [
            f"Platform: {platform.system()} {platform.release()}",
            f"Python: {platform.python_version()}",
            f"Makine: {platform.machine()}",
            f"CPU Cekirdek: {psutil.cpu_count()}",
            f"Toplam RAM: {psutil.virtual_memory().total / (1024**3):.1f} GB"
        ]

        for info in sys_info:
            info_label = Gtk.Label(label=info)
            info_label.add_css_class("metric-label")
            info_label.set_halign(Gtk.Align.START)
            info_group.append(info_label)

        box.append(info_group)

        scroll.set_child(box)
        return scroll

    def _create_setting_row(self, title: str, desc: str, default: bool, setting_key: str) -> Gtk.Widget:
        """Create a settings row with working switch"""
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        row.add_css_class("module-row")

        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)

        title_label = Gtk.Label(label=title)
        title_label.add_css_class("module-name")
        title_label.set_halign(Gtk.Align.START)
        text_box.append(title_label)

        desc_label = Gtk.Label(label=desc)
        desc_label.add_css_class("metric-label")
        desc_label.set_halign(Gtk.Align.START)
        text_box.append(desc_label)

        row.append(text_box)

        switch = Gtk.Switch()
        switch.set_active(default)
        switch.connect("state-set", self._on_setting_changed, setting_key)
        row.append(switch)

        return row

    def _on_setting_changed(self, switch, state, setting_key: str):
        """Handle setting change"""
        if "settings" not in self.config:
            self.config["settings"] = {}

        self.config["settings"][setting_key] = state
        self._save_config()

        self._log_event(f"Ayar degistirildi: {setting_key} = {state}", "info")

        # Apply setting immediately
        if setting_key == "ghost_mode" and state:
            self._apply_ghost_mode()
        elif setting_key == "auto_tor" and state:
            self._control_tor("start")

        return False

    def _apply_ghost_mode(self):
        """Apply ghost mode settings"""
        self._log_event("Ghost Mode aktif - izler siliniyor...", "warning")
        threading.Thread(target=self._do_ghost_cleanup, daemon=True).start()

    def _do_ghost_cleanup(self):
        """Clean up traces for ghost mode"""
        try:
            # Clear bash history
            subprocess.run("history -c 2>/dev/null", shell=True)
            # Clear recent files
            subprocess.run("rm -rf ~/.local/share/recently-used.xbel 2>/dev/null", shell=True)
            GLib.idle_add(self._log_event, "Ghost Mode: Izler temizlendi", "info")
            GLib.idle_add(self._notify, "Ghost Mode", "Sistem izleri temizlendi")
        except Exception as e:
            GLib.idle_add(self._log_event, f"Ghost Mode hatasi: {e}", "error")

    def _start_service(self, script_name: str):
        """Start a TSUNAMI service"""
        def do_start():
            script_path = TSUNAMI_HOME / script_name
            if script_name == "dalga_web.py":
                script_path = TSUNAMI_HOME / "dalga_web.py"
            elif script_name == "network_guardian.py":
                script_path = TSUNAMI_HOME / "scripts" / "network_guardian.py"
            elif script_name == "tsunami_defender.py":
                script_path = TSUNAMI_HOME / "scripts" / "tsunami_defender.py"

            GLib.idle_add(self._log_event, f"Servis baslatiliyor: {script_name}", "info")

            try:
                subprocess.Popen(
                    ["python3", str(script_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=str(TSUNAMI_HOME)
                )
                GLib.idle_add(self._log_event, f"Servis baslatildi: {script_name}", "info")
                GLib.idle_add(self._notify, "Servis Baslatildi", script_name)
            except Exception as e:
                GLib.idle_add(self._log_event, f"Servis hatasi: {e}", "error")

        threading.Thread(target=do_start, daemon=True).start()

    def _control_tor(self, action: str):
        """Start or stop TOR service"""
        def do_control():
            GLib.idle_add(self._log_event, f"TOR {action}...", "info")
            try:
                result = subprocess.run(
                    ["sudo", "systemctl", action, "tor"],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0:
                    GLib.idle_add(self._log_event, f"TOR {action} basarili", "info")
                    GLib.idle_add(self._notify, "TOR", f"TOR {action} edildi")
                else:
                    GLib.idle_add(self._log_event, f"TOR {action} hatasi", "error")
            except Exception as e:
                GLib.idle_add(self._log_event, f"TOR hatasi: {e}", "error")

        threading.Thread(target=do_control, daemon=True).start()

    def _create_panel(self, title: str) -> Gtk.Box:
        """Create a HUD panel with title - RESPONSIVE"""
        panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        panel.add_css_class("hud-panel")
        panel.set_hexpand(True)

        title_label = Gtk.Label(label=title)
        title_label.add_css_class("panel-title")
        title_label.set_halign(Gtk.Align.START)
        panel.append(title_label)

        return panel

    def _on_window_resize(self, window, param):
        """Handle window resize for responsive layout"""
        # This is called when window size changes
        # GTK4's FlowBox handles most responsive behavior automatically
        pass

    def _initial_load(self) -> bool:
        """Initial data load after UI is ready"""
        try:
            self._refresh_threats_tab()
            self._refresh_network_tab()
            self._log_event("Dashboard baslatildi - Tum sistemler aktif", "info")
            self._notify("TSUNAMI Nirvana", "Dashboard aktif - Izleme basladi", "normal")
            logger.info("Dashboard initial load completed successfully")
        except PermissionError as e:
            logger.error(f"Permission error during initial load: {e}")
            self._log_event(f"Yetki hatasi: {e}", "error")
        except Exception as e:
            logger.error(f"Initial load error: {e}")
            self._log_event(f"Baslangic hatasi: {e}", "error")
        return False  # Don't repeat

    def _refresh_data(self) -> bool:
        """Refresh all dashboard data - called every second"""
        try:
            # CPU
            cpu = psutil.cpu_percent(interval=None)
            self.cpu_label.set_text(f"{cpu:.0f}%")
            self.cpu_graph.add_value(cpu)

            # RAM
            mem = psutil.virtual_memory()
            self.ram_gauge.set_value(mem.percent)
            self.ram_label.set_text(f"{mem.used / (1024**3):.1f} / {mem.total / (1024**3):.1f} GB")

            # Disk
            disk = psutil.disk_usage('/')
            self.disk_gauge.set_value(disk.percent)
            self.disk_label.set_text(f"{disk.used / (1024**3):.0f} / {disk.total / (1024**3):.0f} GB")

            # Network
            now = datetime.now()
            net_io = psutil.net_io_counters()
            time_diff = (now - self.last_net_time).total_seconds()
            if time_diff > 0:
                bytes_in = (net_io.bytes_recv - self.last_net_io.bytes_recv) / time_diff
                bytes_out = (net_io.bytes_sent - self.last_net_io.bytes_sent) / time_diff

                self.net_in_label.set_text(self._format_speed(bytes_in))
                self.net_out_label.set_text(self._format_speed(bytes_out))

            self.last_net_io = net_io
            self.last_net_time = now

            # Connection count
            connections = len(psutil.net_connections(kind='inet'))
            self.conn_count_label.set_text(str(connections))

            # Module status
            self._check_modules()

            # Update network tab data (every 5 seconds)
            if not hasattr(self, '_net_refresh_counter'):
                self._net_refresh_counter = 0
            self._net_refresh_counter += 1
            if self._net_refresh_counter >= 5:
                self._net_refresh_counter = 0
                self._refresh_network_tab()
                self._refresh_threats_tab()

            # Update status bar
            self.status_label.set_text(
                f"SISTEM AKTIF | CPU: {cpu:.0f}% | RAM: {mem.percent:.0f}% | "
                f"Baglantilar: {connections} | Son: {now.strftime('%H:%M:%S')}"
            )

            # Check for threats
            self._detect_threats(cpu, mem.percent, connections)

        except Exception as e:
            self._log_event(f"Veri yenileme hatasi: {e}", "error")

        return True  # Continue timer

    def _detect_threats(self, cpu: float, ram: float, connections: int):
        """Detect potential security threats"""
        # High CPU warning
        if cpu > 90:
            if not hasattr(self, '_cpu_warned') or not self._cpu_warned:
                self._add_threat_item("CPU", f"Kritik CPU kullanimi: {cpu:.0f}%", "high")
                self._notify("Yuksek CPU", f"CPU kullanimi %{cpu:.0f}", "critical")
                self._cpu_warned = True
        else:
            self._cpu_warned = False

        # High RAM warning
        if ram > 90:
            if not hasattr(self, '_ram_warned') or not self._ram_warned:
                self._add_threat_item("RAM", f"Kritik RAM kullanimi: {ram:.0f}%", "high")
                self._ram_warned = True
        else:
            self._ram_warned = False

        # Too many connections warning
        if connections > 100:
            if not hasattr(self, '_conn_warned') or not self._conn_warned:
                self._add_threat_item("NETWORK", f"Cok fazla baglanti: {connections}", "medium")
                self._conn_warned = True
        else:
            self._conn_warned = False

    def _refresh_network_tab(self):
        """Refresh network connections list"""
        if not hasattr(self, 'net_conn_list') or not self.net_conn_list:
            return

        # Clear existing items
        child = self.net_conn_list.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.net_conn_list.remove(child)
            child = next_child

        try:
            # Get active connections
            connections = psutil.net_connections(kind='inet')
            shown = 0

            for conn in connections:
                if shown >= 30:  # Limit to 30 connections
                    break
                if conn.status != 'ESTABLISHED' and conn.status != 'LISTEN':
                    continue

                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                row.add_css_class("module-row")

                # Status indicator
                status_color = "led-active" if conn.status == 'ESTABLISHED' else "led-warning"
                status = Gtk.Label(label=f"[{conn.status[:4]}]")
                status.add_css_class(status_color)
                status.set_size_request(60, -1)
                row.append(status)

                # Local address
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                local = Gtk.Label(label=local_addr)
                local.add_css_class("metric-label")
                local.set_size_request(150, -1)
                local.set_halign(Gtk.Align.START)
                row.append(local)

                # Arrow
                arrow = Gtk.Label(label="→")
                arrow.add_css_class("led-active")
                row.append(arrow)

                # Remote address
                if conn.raddr:
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                else:
                    remote_addr = "*:*"
                remote = Gtk.Label(label=remote_addr)
                remote.add_css_class("module-name")
                remote.set_hexpand(True)
                remote.set_halign(Gtk.Align.START)
                row.append(remote)

                # PID
                pid_label = Gtk.Label(label=f"PID:{conn.pid or '-'}")
                pid_label.add_css_class("metric-label")
                row.append(pid_label)

                self.net_conn_list.append(row)
                shown += 1

            # Update interface stats
            self._refresh_interface_stats()

        except Exception as e:
            error_label = Gtk.Label(label=f"Hata: {e}")
            error_label.add_css_class("led-inactive")
            self.net_conn_list.append(error_label)

    def _refresh_interface_stats(self):
        """Refresh network interface statistics"""
        if not hasattr(self, 'iface_stats') or not self.iface_stats:
            return

        # Clear existing
        child = self.iface_stats.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.iface_stats.remove(child)
            child = next_child

        try:
            net_if_stats = psutil.net_if_stats()
            net_if_addrs = psutil.net_if_addrs()
            net_io = psutil.net_io_counters(pernic=True)

            for iface_name, stats in net_if_stats.items():
                if iface_name == 'lo':
                    continue

                panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                panel.add_css_class("module-row")

                # Interface name and status
                header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                name = Gtk.Label(label=iface_name)
                name.add_css_class("module-name")
                name.set_hexpand(True)
                name.set_halign(Gtk.Align.START)
                header.append(name)

                status_text = "UP" if stats.isup else "DOWN"
                status_class = "led-active" if stats.isup else "led-inactive"
                status = Gtk.Label(label=status_text)
                status.add_css_class(status_class)
                header.append(status)
                panel.append(header)

                # IP Address
                if iface_name in net_if_addrs:
                    for addr in net_if_addrs[iface_name]:
                        if addr.family.name == 'AF_INET':
                            ip_label = Gtk.Label(label=f"IP: {addr.address}")
                            ip_label.add_css_class("metric-label")
                            ip_label.set_halign(Gtk.Align.START)
                            panel.append(ip_label)
                            break

                # Speed
                if stats.speed > 0:
                    speed_label = Gtk.Label(label=f"Hiz: {stats.speed} Mbps")
                    speed_label.add_css_class("metric-label")
                    speed_label.set_halign(Gtk.Align.START)
                    panel.append(speed_label)

                # I/O Stats
                if iface_name in net_io:
                    io = net_io[iface_name]
                    io_label = Gtk.Label(label=f"RX: {io.bytes_recv / (1024**2):.1f} MB | TX: {io.bytes_sent / (1024**2):.1f} MB")
                    io_label.add_css_class("metric-label")
                    io_label.set_halign(Gtk.Align.START)
                    panel.append(io_label)

                self.iface_stats.append(panel)

        except Exception as e:
            error_label = Gtk.Label(label=f"Hata: {e}")
            error_label.add_css_class("led-inactive")
            self.iface_stats.append(error_label)

    def _refresh_threats_tab(self):
        """Refresh threats tab with comprehensive threat detection"""
        if not hasattr(self, 'full_threat_list') or not self.full_threat_list:
            return

        # Clear existing
        child = self.full_threat_list.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.full_threat_list.remove(child)
            child = next_child

        threats_found = []

        try:
            # Check for suspicious processes
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'connections']):
                try:
                    info = proc.info
                    # High CPU process
                    if info['cpu_percent'] and info['cpu_percent'] > 50:
                        threats_found.append({
                            'level': 'high' if info['cpu_percent'] > 80 else 'medium',
                            'source': 'PROCESS',
                            'message': f"{info['name']} (PID: {info['pid']}) CPU: {info['cpu_percent']:.0f}%"
                        })
                    # High memory process
                    if info['memory_percent'] and info['memory_percent'] > 20:
                        threats_found.append({
                            'level': 'medium',
                            'source': 'MEMORY',
                            'message': f"{info['name']} RAM: {info['memory_percent']:.1f}%"
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Check for suspicious connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # External connections
                    ip = conn.raddr.ip
                    if not ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.')):
                        # Check for suspicious ports
                        if conn.raddr.port in [4444, 5555, 6666, 31337, 12345]:
                            threats_found.append({
                                'level': 'critical',
                                'source': 'NETWORK',
                                'message': f"Supeli port baglantisi: {ip}:{conn.raddr.port}"
                            })
                        elif conn.raddr.port < 1024 and conn.raddr.port not in [80, 443, 22, 53]:
                            threats_found.append({
                                'level': 'medium',
                                'source': 'NETWORK',
                                'message': f"Dusuk port baglantisi: {ip}:{conn.raddr.port}"
                            })

            # Check listening ports
            listening_ports = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    listening_ports.add(conn.laddr.port)

            # Suspicious listening ports
            suspicious_listen = [p for p in listening_ports if p in [4444, 5555, 6666, 31337, 12345, 1234]]
            for port in suspicious_listen:
                threats_found.append({
                    'level': 'critical',
                    'source': 'LISTENER',
                    'message': f"Supeli port dinleniyor: {port}"
                })

            # Count threats by level
            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for t in threats_found:
                if t['level'] in counts:
                    counts[t['level']] += 1

            # Update count labels
            if hasattr(self, 'threat_critical_count'):
                self.threat_critical_count.set_text(str(counts['critical']))
            if hasattr(self, 'threat_high_count'):
                self.threat_high_count.set_text(str(counts['high']))
            if hasattr(self, 'threat_medium_count'):
                self.threat_medium_count.set_text(str(counts['medium']))
            if hasattr(self, 'threat_low_count'):
                self.threat_low_count.set_text(str(counts['low']))
            if hasattr(self, 'threat_count_label'):
                total = sum(counts.values())
                self.threat_count_label.set_text(f"{total} Tehdit")
                if counts['critical'] > 0:
                    self.threat_count_label.remove_css_class("led-active")
                    self.threat_count_label.remove_css_class("led-warning")
                    self.threat_count_label.add_css_class("led-inactive")
                elif total > 0:
                    self.threat_count_label.remove_css_class("led-active")
                    self.threat_count_label.remove_css_class("led-inactive")
                    self.threat_count_label.add_css_class("led-warning")
                else:
                    self.threat_count_label.remove_css_class("led-warning")
                    self.threat_count_label.remove_css_class("led-inactive")
                    self.threat_count_label.add_css_class("led-active")

            # Add threats to UI
            if not threats_found:
                no_threat = Gtk.Label(label="Tehdit tespit edilmedi - Sistem guvenli")
                no_threat.add_css_class("led-active")
                no_threat.set_margin_top(20)
                self.full_threat_list.append(no_threat)

                # Send positive notification
                self._notify("Sistem Guvenli", "Tehdit taramasi tamamlandi - Sorun yok", "low")
            else:
                # Sort by level
                level_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                threats_found.sort(key=lambda x: level_order.get(x['level'], 5))

                for threat in threats_found[:50]:  # Limit to 50
                    self._add_threat_to_full_list(threat)

                # Send notification for critical threats
                if counts['critical'] > 0:
                    self._notify("KRITIK TEHDIT!", f"{counts['critical']} kritik tehdit tespit edildi!", "critical")
                elif counts['high'] > 0:
                    self._notify("Tehdit Tespit", f"{counts['high']} yuksek seviye tehdit", "normal")

        except Exception as e:
            error_label = Gtk.Label(label=f"Tarama hatasi: {e}")
            error_label.add_css_class("led-inactive")
            self.full_threat_list.append(error_label)

    def _add_threat_to_full_list(self, threat: Dict):
        """Add a threat to the full threats list"""
        item = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        item.add_css_class("threat-item")
        item.add_css_class(f"threat-{threat['level']}")

        # Level badge
        level_colors = {
            'critical': 'badge-kritik',
            'high': 'badge-yuksek',
            'medium': 'badge-orta',
            'low': 'badge-dusuk',
            'info': 'badge-bilgi'
        }
        level_label = Gtk.Label(label=threat['level'].upper())
        level_label.add_css_class("status-badge")
        level_label.add_css_class(level_colors.get(threat['level'], 'badge-bilgi'))
        level_label.set_size_request(70, -1)
        item.append(level_label)

        # Source
        source_label = Gtk.Label(label=f"[{threat['source']}]")
        source_label.add_css_class("led-warning")
        source_label.set_size_request(80, -1)
        item.append(source_label)

        # Message
        msg_label = Gtk.Label(label=threat['message'])
        msg_label.add_css_class("module-name")
        msg_label.set_hexpand(True)
        msg_label.set_halign(Gtk.Align.START)
        msg_label.set_ellipsize(Pango.EllipsizeMode.END)
        item.append(msg_label)

        # Action button
        action_btn = Gtk.Button(label="INCELE")
        action_btn.add_css_class("action-btn")
        action_btn.set_size_request(70, -1)
        item.append(action_btn)

        self.full_threat_list.append(item)

    def _format_speed(self, bytes_per_sec: float) -> str:
        """Format network speed"""
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.0f} B/s"
        elif bytes_per_sec < 1024 * 1024:
            return f"{bytes_per_sec / 1024:.1f} KB/s"
        else:
            return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"

    def _check_modules(self):
        """Check status of all modules - SECURITY HARDENED"""
        # Security: Whitelist of allowed module check commands
        ALLOWED_MODULE_CHECKS = {
            "pgrep -f dalga_web.py",
            "pgrep -f network_guardian.py",
            "pgrep -f tsunami_defender.py",
            "systemctl is-active tor",
        }

        for name, data in self.module_widgets.items():
            check = data["check"]
            label = data["label"]

            try:
                if check.startswith("config:"):
                    # Read from config - validate path
                    path = check.split(":")[1]
                    # Security: Only allow alphanumeric, underscores and dots in config paths
                    if not all(c.isalnum() or c in '._ ' for c in path):
                        logger.warning(f"Invalid config path: {path}")
                        continue
                    parts = path.split(".")
                    value = self.config
                    for part in parts:
                        value = value.get(part, {}) if isinstance(value, dict) else False
                    is_active = bool(value)
                elif check in ALLOWED_MODULE_CHECKS:
                    # Security: Only run whitelisted commands
                    # Use list format without shell=True
                    args = shlex.split(check)
                    result = subprocess.run(
                        args,
                        capture_output=True,
                        timeout=2
                    )
                    is_active = result.returncode == 0
                else:
                    # Unknown check command - log and skip
                    logger.warning(f"Unknown module check: {check}")
                    continue

                # Update label
                label.remove_css_class("badge-aktif")
                label.remove_css_class("badge-pasif")
                label.remove_css_class("badge-uyari")

                if is_active:
                    label.set_text("AKTIF")
                    label.add_css_class("badge-aktif")
                else:
                    label.set_text("PASIF")
                    label.add_css_class("badge-pasif")

            except subprocess.TimeoutExpired:
                label.set_text("TIMEOUT")
                label.add_css_class("badge-uyari")
            except PermissionError:
                label.set_text("YETKI")
                label.add_css_class("badge-uyari")
            except FileNotFoundError:
                label.set_text("YOK")
                label.add_css_class("badge-pasif")
            except Exception as e:
                label.set_text("HATA")
                label.add_css_class("badge-pasif")
                logger.error(f"Module check error for {name}: {e}")

    def _add_threat_item(self, source: str, message: str, level: str = "info"):
        """Add a threat item to the threat list"""
        item = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        item.add_css_class("threat-item")
        item.add_css_class(f"threat-{level}")

        time_label = Gtk.Label(label=datetime.now().strftime("%H:%M:%S"))
        time_label.add_css_class("metric-label")
        item.append(time_label)

        source_label = Gtk.Label(label=f"[{source}]")
        source_label.add_css_class("led-warning" if level != "info" else "led-active")
        item.append(source_label)

        msg_label = Gtk.Label(label=message)
        msg_label.add_css_class("module-name")
        msg_label.set_hexpand(True)
        msg_label.set_halign(Gtk.Align.START)
        msg_label.set_ellipsize(Pango.EllipsizeMode.END)
        item.append(msg_label)

        self.threat_list.prepend(item)

        # Keep only last 20 items - GTK4 proper iteration
        count = 0
        child = self.threat_list.get_first_child()
        while child:
            count += 1
            child = child.get_next_sibling()

        if count > 20:
            # Remove oldest items (from the end)
            child = self.threat_list.get_last_child()
            while count > 20 and child:
                prev_child = child.get_prev_sibling()
                self.threat_list.remove(child)
                count -= 1
                child = prev_child

    def _log_event(self, message: str, level: str = "info"):
        """Log an event"""
        if self.event_list:
            item = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            item.add_css_class("module-row")

            time_label = Gtk.Label(label=datetime.now().strftime("%H:%M:%S"))
            time_label.add_css_class("metric-label")
            item.append(time_label)

            level_colors = {
                "info": "led-active",
                "warning": "led-warning",
                "error": "led-inactive"
            }
            level_label = Gtk.Label(label=f"[{level.upper()}]")
            level_label.add_css_class(level_colors.get(level, "led-active"))
            item.append(level_label)

            msg_label = Gtk.Label(label=message)
            msg_label.add_css_class("module-name")
            msg_label.set_hexpand(True)
            msg_label.set_halign(Gtk.Align.START)
            item.append(msg_label)

            self.event_list.prepend(item)

    def _clear_events(self, button):
        """Clear events list"""
        while True:
            child = self.event_list.get_first_child()
            if child:
                self.event_list.remove(child)
            else:
                break
        self._log_event("Olay listesi temizlendi", "info")

    def _on_tor_new_identity(self, button):
        """Request new TOR identity"""
        def do_tor_refresh():
            try:
                # Try to signal TOR for new identity
                result = subprocess.run(
                    ["sudo", "killall", "-HUP", "tor"],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    GLib.idle_add(self._notify, "TOR Yenilendi", "Yeni devre olusturuldu")
                    GLib.idle_add(self._log_event, "TOR kimligi yenilendi", "info")
                    GLib.idle_add(self._add_threat_item, "TOR", "Yeni kimlik alindi", "info")
                else:
                    GLib.idle_add(self._notify, "TOR Hatasi", "Yenileme basarisiz")
                    GLib.idle_add(self._log_event, "TOR yenileme hatasi", "error")
            except Exception as e:
                GLib.idle_add(self._log_event, f"TOR hatasi: {e}", "error")

        threading.Thread(target=do_tor_refresh, daemon=True).start()

    def _on_ghost_toggle(self, switch, state):
        """Toggle ghost mode"""
        if "stealth" not in self.config:
            self.config["stealth"] = {}

        self.config["stealth"]["ghost_mode"] = state
        self._save_config()

        status = "AKTIF" if state else "PASIF"
        self._notify("Ghost Mode", f"Ghost Mode {status}")
        self._log_event(f"Ghost Mode: {status}", "info")
        self._add_threat_item("GHOST", f"Mode {status.lower()}", "info")

        return False

    def _on_emergency_scan(self, button):
        """Run emergency security scan"""
        def do_scan():
            GLib.idle_add(self._log_event, "Acil tarama baslatildi...", "warning")
            GLib.idle_add(self._add_threat_item, "SCAN", "Acil tarama baslatildi", "medium")

            try:
                # Check for suspicious processes
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        if proc.info['cpu_percent'] and proc.info['cpu_percent'] > 80:
                            GLib.idle_add(
                                self._add_threat_item, "SCAN",
                                f"Yuksek CPU: {proc.info['name']} ({proc.info['cpu_percent']:.0f}%)",
                                "high"
                            )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Check connections
                suspicious = 0
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        # Count external connections
                        if not conn.raddr.ip.startswith(('127.', '192.168.', '10.')):
                            suspicious += 1

                if suspicious > 10:
                    GLib.idle_add(
                        self._add_threat_item, "SCAN",
                        f"{suspicious} harici baglanti tespit edildi",
                        "medium"
                    )

                GLib.idle_add(self._log_event, "Acil tarama tamamlandi", "info")
                GLib.idle_add(self._notify, "Tarama Tamamlandi", f"Sonuc: {suspicious} harici baglanti")

            except Exception as e:
                GLib.idle_add(self._log_event, f"Tarama hatasi: {e}", "error")

        threading.Thread(target=do_scan, daemon=True).start()

    def _on_command_execute(self, widget):
        """Execute command from terminal"""
        cmd = self.cmd_entry.get_text().strip()
        if not cmd:
            return

        self.cmd_entry.set_text("")
        self._run_terminal_command(cmd)

    def _run_terminal_command(self, cmd: str):
        """Run a command and show output in terminal - SECURITY HARDENED"""
        def do_run():
            try:
                # Security: Validate command against whitelist
                is_allowed = cmd in ALLOWED_COMMANDS or cmd in SUDO_COMMANDS
                is_safe_command = self._is_safe_command(cmd)

                if not is_allowed and not is_safe_command:
                    GLib.idle_add(self._append_terminal, f"\n> {cmd}\n")
                    GLib.idle_add(self._append_terminal,
                        "[GUVENLIK] Bu komut izin listesinde degil.\n"
                        "Izin verilen komutlar icin butonlari kullanin.\n")
                    GLib.idle_add(self._log_event, f"Engellenen komut: {cmd}", "warning")
                    return

                # Append command to terminal
                GLib.idle_add(self._append_terminal, f"\n> {cmd}\n")

                # Security: Use shlex to safely split command (avoid shell=True)
                try:
                    # For piped commands, we still need shell but with validation
                    if '|' in cmd or '&&' in cmd or '>' in cmd:
                        result = subprocess.run(
                            cmd, shell=True,
                            capture_output=True, text=True,
                            timeout=30,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
                        )
                    else:
                        # Safe execution without shell
                        args = shlex.split(cmd)
                        result = subprocess.run(
                            args,
                            capture_output=True, text=True,
                            timeout=30
                        )
                except ValueError as e:
                    GLib.idle_add(self._append_terminal, f"\n[KOMUT HATASI: {e}]\n")
                    return

                output = result.stdout + result.stderr
                if output:
                    GLib.idle_add(self._append_terminal, output)
                else:
                    GLib.idle_add(self._append_terminal, "(Cikis yok)\n")

            except subprocess.TimeoutExpired:
                GLib.idle_add(self._append_terminal, "\n[TIMEOUT: 30s]\n")
            except PermissionError:
                GLib.idle_add(self._append_terminal, "\n[YETKI HATASI: sudo gerekebilir]\n")
            except FileNotFoundError:
                GLib.idle_add(self._append_terminal, "\n[HATA: Komut bulunamadi]\n")
            except Exception as e:
                GLib.idle_add(self._append_terminal, f"\n[HATA: {e}]\n")
                logger.error(f"Terminal command error: {e}")

        threading.Thread(target=do_run, daemon=True).start()

    def _is_safe_command(self, cmd: str) -> bool:
        """Check if command is safe to execute"""
        # Dangerous patterns
        dangerous_patterns = [
            "rm -rf /", "rm -rf ~", "rm -rf .",
            ":(){ :|:& };:", "fork bomb",
            "> /dev/sd", "dd if=", "mkfs.",
            "chmod -R 777 /", "chown -R",
            "wget", "curl.*|.*sh", "curl.*|.*bash",
            "eval", "exec", "`", "$(",
            "nc -e", "bash -i", "/dev/tcp",
        ]
        cmd_lower = cmd.lower()
        for pattern in dangerous_patterns:
            if pattern in cmd_lower:
                return False
        return True

    def _append_terminal(self, text: str):
        """Append text to terminal buffer"""
        end = self.terminal_buffer.get_end_iter()
        self.terminal_buffer.insert(end, text)

        # Auto-scroll to bottom
        end = self.terminal_buffer.get_end_iter()
        self.terminal_view.scroll_to_iter(end, 0, False, 0, 0)

    def _notify(self, title: str, message: str, urgency: str = "normal"):
        """Send desktop notification with sound"""
        # Check if notifications are enabled
        settings = self.config.get("settings", {})
        if not settings.get("desktop_notifications", True):
            return

        try:
            # Choose icon based on urgency
            icon_map = {
                "low": "dialog-information",
                "normal": "dialog-warning",
                "critical": "dialog-error"
            }
            icon = icon_map.get(urgency, "dialog-information")

            notification = Notify.Notification.new(
                f"🌊 TSUNAMI: {title}",
                message,
                icon
            )

            urgency_map = {
                "low": Notify.Urgency.LOW,
                "normal": Notify.Urgency.NORMAL,
                "critical": Notify.Urgency.CRITICAL
            }
            notification.set_urgency(urgency_map.get(urgency, Notify.Urgency.NORMAL))

            # Set timeout (0 for critical = stays until dismissed)
            if urgency == "critical":
                notification.set_timeout(0)
            else:
                notification.set_timeout(5000)

            notification.show()

            # Log to events
            self._log_event(f"[BILDIRIM] {title}: {message}", "info")

            # Play sound for critical notifications
            if urgency == "critical" and settings.get("sound_alerts", False):
                threading.Thread(target=self._play_alert_sound, daemon=True).start()

            # Add to notification history
            if hasattr(self, 'notification_history'):
                self.notification_history.append({
                    'time': datetime.now(),
                    'title': title,
                    'message': message,
                    'urgency': urgency
                })
                # Keep last 50
                if len(self.notification_history) > 50:
                    self.notification_history.pop(0)

        except Exception as e:
            print(f"Notification error: {e}")

    def _play_alert_sound(self):
        """Play alert sound for critical notifications"""
        try:
            # Try paplay (PulseAudio)
            subprocess.run(
                ["paplay", "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"],
                capture_output=True, timeout=5
            )
        except Exception:
            try:
                # Fallback to aplay
                subprocess.run(
                    ["aplay", "-q", "/usr/share/sounds/alsa/Front_Center.wav"],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass  # No sound available


def main():
    app = TsunamiNirvanaDashboard()
    return app.run(None)


if __name__ == "__main__":
    main()
