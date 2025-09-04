# firewall_simulation_project

This is a simple firewall simulator built using Python and Tkinter. It allows you to create firewall rules, simulate network traffic, and monitor packets being allowed or blocked — all in a graphical user interface.

---

## Features

- Add/Remove firewall rules (IP, Port, Protocol based)
- Simulate random incoming network traffic
- View real-time traffic logs (Allowed vs Blocked)
- Display live statistics (total, allowed, blocked packets)
- Color-coded traffic monitor (green = allowed, red = blocked)
- Simple tabbed interface (Rules, Monitor, Stats)

---

## Files

- `main.py` - Launches the application
- `firewall_engine.py` - Core logic (rules, packet handling)
- `firewall_gui.py` - Tkinter GUI (rules tab, monitor, statistics)

---

## Requirements

- Python 3.8+
- Tkinter (usually comes with Python)
  
> **Linux Users:**  
> Run `sudo apt install python3-tk` if Tkinter is not installed.

---

## How to Run

```bash
git clone https://github.com/your-username/firewall-simulator.git
cd firewall-simulator
python main.py

