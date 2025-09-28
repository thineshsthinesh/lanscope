# 🌐 Cumulative Network Topology Scanner
A web-based tool for scanning and visualizing network topology. It performs **cumulative scans**, stores results persistently in SQLite, and provides an interactive dashboard to explore discovered hosts, routes, and internet paths.

## ✨ Features
- **Cumulative scanning** – like Zenmap, keeps history across runs  
- **Adaptive subnet discovery** – handles `/24` and splits `/16` into multiple `/24`s  
- **Persistent storage** – hosts, routes, links, and scans stored in SQLite  
- **Host analysis** – RTT, hostname, MAC lookup, device type detection  
- **Traceroute mapping** – to both internal hosts and internet (e.g. `8.8.8.8`)  
- **Interactive topology UI** – drag nodes, zoom, pan, reset view  
- **Export / Import** – save and reload scan data (JSON)  
- **Scan history** – compare past scans  

## 🖥️ Screenshots
### Dashboard
![Dashboard Screenshot](https://github.com/thineshsthinesh/external/blob/main/Screenshot%202025-09-28%20184803.png)

## ⚙️ Requirements
- Python **3.8+**  
- Flask  
- Flask-SocketIO  
- SQLite3  

Install dependencies:
    
    pip install flask flask-socketio

## 🚀 Usage
1. **Start the backend server**:
    
        python app.py

2. **Open the dashboard** in your browser:
    
        http://localhost:5000

3. **Enter a subnet** (e.g. `192.168.1.0/24`) and click **Start Scan**.  
4. Use the sidebar to view discovered hosts, scan history, and export/import options.  
5. Use the graph to drag and reposition nodes, zoom in/out, reset view, and inspect hosts/traceroutes.  

## 📂 Project Structure
    .
    ├── app.py               # Flask backend with cumulative scanning logic
    ├── dashboard.html       # Frontend UI with D3.js visualization
    ├── requirements.txt     # (optional) dependencies list
    ├── screenshots/         # place for UI screenshots
    └── network_topology.db  # SQLite storage (auto-created)

## 📤 Export / 📥 Import
- **Export** results to JSON (with optional node positions).  
- **Import** JSON back (merge with existing or replace).  
These actions can be triggered from the dashboard or via API endpoints.

## 🔌 API Endpoints
| Endpoint            | Method | Description |
|---------------------|--------|-------------|
| `/start_scan`       | POST   | Start a new scan (requires JSON body: `{"target": "192.168.1.0/24"}`) |
| `/stop_scan`        | POST   | Stop the current scan |
| `/export`           | GET    | Export scan data as JSON (`?positions=true/false`) |
| `/import`           | POST   | Import JSON scan data (supports merge mode) |
| `/clear_cumulative` | POST   | Clear all cumulative scan data |

## 🛠️ Notes
- On `/16` networks, the scanner **automatically splits into 256 `/24` subnets** for efficiency.  
- Persistent data is stored in **SQLite (`network_topology.db`)**.  
- Node positions in the graph are remembered between sessions.

## 📜 License
This project is open-source. You may modify and distribute it under your preferred license.
