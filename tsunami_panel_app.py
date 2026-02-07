#!/usr/bin/env python3
"""
TSUNAMI Siber Komuta - Masaüstü Uygulama
Tam pencere kontrolü: Küçült, Büyüt, Kapat
GTK3 + WebKit2 version
"""

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('WebKit2', '4.1')

from gi.repository import Gtk, WebKit2, Gdk, GLib
import sys

class TsunamiWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="🌊 TSUNAMI Siber Komuta Merkezi")
        
        # Pencere ayarları
        self.set_default_size(1400, 900)
        self.set_position(Gtk.WindowPosition.CENTER)
        
        # Dark theme
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)
        
        # Main container
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(main_box)
        
        # Header bar
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_title("TSUNAMI")
        header.set_subtitle("Siber Komuta Merkezi")
        self.set_titlebar(header)
        
        # Status label
        self.status_box = Gtk.Box(spacing=5)
        self.status_dot = Gtk.Label()
        self.status_dot.set_markup('<span foreground="#00ff88">●</span>')
        self.status_label = Gtk.Label(label="BAĞLI")
        self.status_box.pack_start(self.status_dot, False, False, 0)
        self.status_box.pack_start(self.status_label, False, False, 0)
        header.pack_start(self.status_box)
        
        # Buttons
        refresh_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        refresh_btn.set_tooltip_text("Yenile (F5)")
        refresh_btn.connect("clicked", self.on_refresh)
        header.pack_start(refresh_btn)
        
        home_btn = Gtk.Button.new_from_icon_name("go-home-symbolic", Gtk.IconSize.BUTTON)
        home_btn.set_tooltip_text("Ana Sayfa")
        home_btn.connect("clicked", self.go_home)
        header.pack_start(home_btn)
        
        fullscreen_btn = Gtk.Button.new_from_icon_name("view-fullscreen-symbolic", Gtk.IconSize.BUTTON)
        fullscreen_btn.set_tooltip_text("Tam Ekran (F11)")
        fullscreen_btn.connect("clicked", self.toggle_fullscreen)
        header.pack_end(fullscreen_btn)
        
        # TOR indicator
        tor_box = Gtk.Box(spacing=3)
        tor_icon = Gtk.Label()
        tor_icon.set_markup('<span foreground="#9b59b6">🧅</span>')
        tor_label = Gtk.Label()
        tor_label.set_markup('<span foreground="#9b59b6" size="small">TOR</span>')
        tor_box.pack_start(tor_icon, False, False, 0)
        tor_box.pack_start(tor_label, False, False, 0)
        header.pack_end(tor_box)
        
        # WebView
        self.webview = WebKit2.WebView()
        
        # WebView settings
        ws = self.webview.get_settings()
        ws.set_enable_javascript(True)
        ws.set_enable_developer_extras(True)
        ws.set_javascript_can_access_clipboard(True)
        ws.set_enable_smooth_scrolling(True)
        
        # Dark background
        rgba = Gdk.RGBA()
        rgba.parse("#050510")
        self.webview.set_background_color(rgba)
        
        # Load panel
        self.webview.load_uri("http://localhost:8080/panel")
        
        # Monitor load status
        self.webview.connect("load-changed", self.on_load_changed)
        self.webview.connect("load-failed", self.on_load_failed)
        
        # Scrolled window for webview
        scrolled = Gtk.ScrolledWindow()
        scrolled.add(self.webview)
        main_box.pack_start(scrolled, True, True, 0)
        
        # Keyboard shortcuts
        self.connect("key-press-event", self.on_key_press)
        self.connect("delete-event", Gtk.main_quit)
        
        self.is_fullscreen = False
        
    def on_refresh(self, button):
        self.webview.reload()
        
    def go_home(self, button):
        self.webview.load_uri("http://localhost:8080/panel")
        
    def toggle_fullscreen(self, button=None):
        if self.is_fullscreen:
            self.unfullscreen()
        else:
            self.fullscreen()
        self.is_fullscreen = not self.is_fullscreen
        
    def on_key_press(self, widget, event):
        if event.keyval == Gdk.KEY_F11:
            self.toggle_fullscreen()
            return True
        elif event.keyval == Gdk.KEY_F5:
            self.webview.reload()
            return True
        elif event.keyval == Gdk.KEY_Escape and self.is_fullscreen:
            self.toggle_fullscreen()
            return True
        return False
        
    def on_load_changed(self, webview, load_event):
        if load_event == WebKit2.LoadEvent.STARTED:
            self.status_dot.set_markup('<span foreground="#f39c12">●</span>')
            self.status_label.set_text("YÜKLENİYOR")
        elif load_event == WebKit2.LoadEvent.FINISHED:
            self.status_dot.set_markup('<span foreground="#00ff88">●</span>')
            self.status_label.set_text("BAĞLI")
            
    def on_load_failed(self, webview, load_event, uri, error):
        self.status_dot.set_markup('<span foreground="#e74c3c">●</span>')
        self.status_label.set_text("BAĞLANTI HATASI")
        return False

def main():
    win = TsunamiWindow()
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()
