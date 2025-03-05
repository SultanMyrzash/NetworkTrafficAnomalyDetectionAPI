import random

# Global system status
system_status = "OK"

def analyze_packet(packet):
    """Fake ML model that returns a status and updates system status."""
    global system_status
    statuses = ["GOOD", "BAD", "SOMETHING DETECTED"]
    result = random.choice(statuses)

    # If any packet is bad, set system status to "ANOMALY DETECTED"
    if result in ["BAD", "SOMETHING DETECTED"]:
        system_status = "ANOMALY DETECTED"
    else:
        system_status = "OK"

    return result
