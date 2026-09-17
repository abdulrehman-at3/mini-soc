#!/usr/bin/env python3
"""Start the Mini-SOC dashboard: `python run_dashboard.py`."""
import config
from dashboard.app import app

if __name__ == "__main__":
    print(f"Mini-SOC dashboard starting at http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=False)
