#!/bin/bash
# TSUNAMI Panel Launcher

# Check if web server is running
if ! curl -s http://localhost:8080 > /dev/null 2>&1; then
    notify-send -i security-high "TSUNAMI" "Web server başlatılıyor..." 2>/dev/null
    systemctl --user start tsunami-web.service
    sleep 5
fi

# Launch GTK Panel App
python3 /home/lydian/Desktop/TSUNAMI/tsunami_panel_app.py &

notify-send -i security-high "TSUNAMI Panel" "Siber Komuta Merkezi açıldı" 2>/dev/null
