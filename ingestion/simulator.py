import time
import random
import threading
from datetime import datetime
from ingestion.schema import RawAlert
from ingestion.main import ingest_raw_alert

def generate_random_alert() -> RawAlert:
    """Generates a realistic security alert from a random scenario."""
    scenarios = [
        {
            "source": "Splunk SIEM",
            "rule_name": "Outbound connection to Tor exit node",
            "severity": "critical",
            "ioc_type": "ip",
            # We occasionally generate the exact demo IP to trigger default enrichment cache mappings
            "ioc_value": random.choice(["185.220.101.7", f"185.220.101.{random.randint(10, 250)}"])
        },
        {
            "source": "QRadar SIEM",
            "rule_name": "Repeated auth failures across 40 accounts",
            "severity": "high",
            "ioc_value": random.choice(["45.83.64.22", f"45.83.64.{random.randint(10, 250)}"])
        },
        {
            "source": "CrowdStrike EDR",
            "rule_name": "Known-malicious binary hash executed",
            "severity": "medium",
            "ioc_type": "hash",
            "ioc_value": random.choice(["d41d8cd98f00b204e9800998ecf8427e", f"bad_hash_{random.randint(100, 999)}"])
        },
        {
            "source": "Palo Alto Firewall",
            "rule_name": "Port scan detected from internal host",
            "severity": "low",
            "ioc_type": "ip",
            "ioc_value": f"192.0.2.{random.randint(10, 250)}"
        }
    ]
    
    choice = random.choice(scenarios)
    return RawAlert(
        source=choice["source"],
        rule_name=choice["rule_name"],
        severity=choice["severity"],
        ioc_type=choice.get("ioc_type", "ip"),
        ioc_value=choice["ioc_value"],
        received_at=datetime.utcnow().isoformat()
    )

def _simulator_loop():
    print("[*] Background Alert Simulator Loop started.")
    # Wait for the main Flask application to fully start
    time.sleep(10)
    
    while True:
        try:
            alert = generate_random_alert()
            print(f"[*] Simulator: Triggering raw alert: '{alert.rule_name}' from {alert.source}")
            ingest_raw_alert(alert)
        except Exception as e:
            print(f"[!] Error in simulator loop: {e}")
        time.sleep(random.uniform(15.0, 25.0))

def start_simulator():
    """Starts the alert simulator in a background daemon thread."""
    thread = threading.Thread(target=_simulator_loop, daemon=True)
    thread.start()
    return thread
