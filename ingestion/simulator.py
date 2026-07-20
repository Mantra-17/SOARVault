import asyncio
import httpx
import json
import random
import time
from datetime import datetime, timezone
from typing import Dict, Any

class AlertSimulator:
    """Generates mock SIEM payloads mimicking real-world alerts."""
    
    VENDORS = ["Splunk", "QRadar", "Elastic", "CrowdStrike"]

    def _base_alert(self, title: str) -> Dict[str, Any]:
        """Base structure for all generated alerts."""
        vendor = random.choice(self.VENDORS)
        return {
            "vendor": vendor,
            "title": f"[{vendor}] {title}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_severity": random.choice(["high", "medium", "critical", "low", 1, 2, 3, 4, 5]),
            "event_id": f"evt-{random.randint(1000, 9999)}"
        }

    def generate_brute_force(self) -> Dict[str, Any]:
        alert = self._base_alert("Multiple Failed Logins")
        alert.update({
            "source_ip": f"192.168.1.{random.randint(10, 250)}",
            "destination_ip": "10.0.0.5",
            "username": "admin",
            "action": "login_failed",
            "count": random.randint(5, 50)
        })
        return alert

    def generate_malware(self) -> Dict[str, Any]:
        alert = self._base_alert("Malware Detected")
        alert.update({
            "hostname": f"DESKTOP-{random.randint(100,999)}",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",
            "file_path": "C:\\Windows\\Temp\\malicious.exe",
            "action": "quarantined"
        })
        return alert

    def generate_ddos(self) -> Dict[str, Any]:
        alert = self._base_alert("Volumetric DDoS Traffic Detected")
        alert.update({
            "destination_ip": "10.0.0.100",
            "bytes_received": random.randint(1000000, 50000000),
            "protocol": "UDP",
            "action": "allowed"
        })
        return alert

    def generate_insider_threat(self) -> Dict[str, Any]:
        alert = self._base_alert("Unusual Access to Confidential Data")
        alert.update({
            "username": "jdoe",
            "department": "Engineering",
            "file_accessed": "HR_Salaries_2026.xlsx",
            "action": "read"
        })
        return alert

    def generate_data_exfiltration(self) -> Dict[str, Any]:
        alert = self._base_alert("Large Outbound Data Transfer")
        alert.update({
            "source_ip": "10.0.1.50",
            "destination_ip": f"185.10.2.{random.randint(1,200)}",
            "bytes_sent": random.randint(5000000, 20000000),
            "action": "allowed"
        })
        return alert

    def get_random_alert(self) -> Dict[str, Any]:
        generators = [
            self.generate_brute_force,
            self.generate_malware,
            self.generate_ddos,
            self.generate_insider_threat,
            self.generate_data_exfiltration
        ]
        return random.choice(generators)()

async def blast_server(num_requests: int = 100):
    """Blast the FastAPI server with generated alerts."""
    simulator = AlertSimulator()
    url = "http://127.0.0.1:8000/webhook/alert"
    
    print(f"Blasting {url} with {num_requests} requests...")
    start_time = time.time()
    
    async with httpx.AsyncClient() as client:
        tasks = []
        for _ in range(num_requests):
            payload = simulator.get_random_alert()
            tasks.append(client.post(url, json=payload))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    end_time = time.time()
    success = sum(1 for r in results if not isinstance(r, Exception) and r.status_code in (200, 202))
    
    print(f"Finished in {end_time - start_time:.2f} seconds.")
    print(f"Successful requests: {success}/{num_requests}")

if __name__ == "__main__":
    asyncio.run(blast_server(50))
