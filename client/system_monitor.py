import socket
import getpass
import psutil
import win32evtlog


def get_hostname_and_ip():
    hostname = socket.gethostname()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        ip = "127.0.0.1"

    return hostname, ip


last_record = None

def get_latest_event():

    logs = ["System", "Application"]

    for logtype in logs:
        try:
            hand = win32evtlog.OpenEventLog("localhost", logtype)

            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ |
                win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            events = win32evtlog.ReadEventLog(hand, flags, 0)

            if events:
                event = events[0]

                return {
                    "event_id": event.EventID & 0xFFFF,
                    "event_source": event.SourceName,
                    "event_type": event.EventType,
                    "event_time": str(event.TimeGenerated)
                }

        except Exception:
            continue

    return None

def collect_system_snapshot():

    hostname, ip = get_hostname_and_ip()

    event = get_latest_event()
    
    if event is None:
        return None
    
    
    net = psutil.net_io_counters()
    
    return {
    "hostname": hostname,
    "ip_address": ip,
    "logged_in_user": getpass.getuser(),

    "event_id": event["event_id"] if event else 0,
    "event_source": event["event_source"] if event else "",
    "event_type": event["event_type"] if event else "",
    "event_time": event["event_time"] if event else "",

    "cpu_usage": psutil.cpu_percent(interval=1),
    "ram_usage": psutil.virtual_memory().percent,
    "disk_usage": psutil.disk_usage("C:\\").percent,
    "process_count": len(psutil.pids()),

    "failed_logins": 0,
    "firewall_disabled": 0,

    "network_bytes_sent": net.bytes_sent,
    "network_bytes_recv": net.bytes_recv,

    "usb_connected": 0,
}