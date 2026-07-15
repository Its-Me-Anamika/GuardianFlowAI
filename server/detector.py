"""
detector.py
-----------
Windows Event Log based threat detector.
Maps important Windows Event IDs to threat types and severity.
"""

class ThreatDetector:

    def load_model(self):
        # Nothing to load now.
        return True

    def train_synthetic(self):
        pass

    def train_live(self):
        pass

    def analyze(self, log_entry):

        event_id = int(log_entry.get("event_id", 0))

        EVENT_MAP = {

            # Authentication
            4624: ("None", "Low", "Successful login detected."),
            4625: ("Brute Force", "High", "Failed login attempt detected."),

            # User Management
            4720: ("New User Created", "Critical",
                   "A new Windows user account was created."),
            4726: ("User Deleted", "Medium",
                   "A Windows user account was deleted."),

            # Security
            1102: ("Log Tampering", "Critical",
                   "Windows Security log was cleared."),

            # Services
            7045: ("Suspicious Service", "Critical",
                   "A new Windows service was installed."),

            7036: ("Service State Change", "Low",
                   "Windows service changed state."),

            # System
            6008: ("Unexpected Shutdown", "Medium",
                   "Unexpected system shutdown detected."),

            41: ("Kernel Power", "High",
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
            "reason": "No rule exists for this Windows Event ID.",
            "confidence_score": 50,
            "is_anomaly": False
        }