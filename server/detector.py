"""
detector.py
-----------
Windows Event Log based threat detector.
Maps important Windows Event IDs to threat types and severity.
"""

class ThreatDetector:

    def load_model(self):
        return True

    def train_synthetic(self):
        pass

    def train_live(self):
        pass

    def analyze(self, log_entry):

        event_id = int(log_entry.get("event_id", 0))

        cpu = float(log_entry.get("cpu_usage", 0))
        ram = float(log_entry.get("ram_usage", 0))
        failed = int(log_entry.get("failed_logins", 0))
        firewall = int(log_entry.get("firewall_disabled", 0))
        usb = int(log_entry.get("usb_connected", 0))

        # -------------------------
        # LIVE SYSTEM CHECKS
        # -------------------------

        if firewall == 1:
            return {
                "threat_level": "High",
                "threat_type": "Firewall Disabled",
                "reason": "Windows Firewall is disabled.",
                "confidence_score": 98,
                "is_anomaly": True
            }

        if failed >= 5:
            return {
                "threat_level": "High",
                "threat_type": "Brute Force Attack",
                "reason": "Multiple failed login attempts detected.",
                "confidence_score": 95,
                "is_anomaly": True
            }

        if usb == 1:
            return {
                "threat_level": "Medium",
                "threat_type": "USB Device Connected",
                "reason": "A removable USB device was connected.",
                "confidence_score": 90,
                "is_anomaly": True
            }

        if cpu >= 90:
            return {
                "threat_level": "Medium",
                "threat_type": "High CPU Usage",
                "reason": "CPU usage exceeded 90%.",
                "confidence_score": 85,
                "is_anomaly": True
            }

        if ram >= 95:
            return {
                "threat_level": "Medium",
                "threat_type": "High RAM Usage",
                "reason": "RAM usage exceeded 95%.",
                "confidence_score": 85,
                "is_anomaly": True
            }

        # -------------------------
        # WINDOWS EVENT CHECKS
        # -------------------------

        EVENT_MAP = {

            4624: ("None", "Low", "Successful login detected."),

            4625: ("Brute Force", "High",
                   "Failed login attempt detected."),

            4720: ("New User Created", "Critical",
                   "A new Windows user account was created."),

            4726: ("User Deleted", "Medium",
                   "A Windows user account was deleted."),

            1102: ("Log Tampering", "Critical",
                   "Windows Security log was cleared."),

            7045: ("Suspicious Service", "Critical",
                   "A new Windows service was installed."),

            7036: ("Service State Change", "Low",
                   "Windows service changed state."),

            6008: ("Unexpected Shutdown", "Medium",
                   "Unexpected shutdown detected."),

            41: ("Kernel Power Failure", "High",
                 "Kernel power failure detected."),

            105: ("Kernel Power Warning", "Medium",
                  "Kernel power warning detected.")
        }

        if event_id in EVENT_MAP:

            threat_type, level, reason = EVENT_MAP[event_id]

            return {
                "threat_level": level,
                "threat_type": threat_type,
                "reason": reason,
                "confidence_score": 100,
                "is_anomaly": threat_type != "None"
            }

        return {
            "threat_level": "Low",
            "threat_type": "Unknown Event",
            "reason": "No suspicious activity detected.",
            "confidence_score": 50,
            "is_anomaly": False
        }