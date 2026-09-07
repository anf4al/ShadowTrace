"""
detector.py - Rule-Based Detection Engine for ShadowTrace.

This module analyzes security event logs using predefined rules and patterns
to detect suspicious cyber activity, such as brute-force logins and
correlated multi-stage attack sequences.
"""

from datetime import datetime


def detect_failed_logins(events, threshold=3):
    """
    Scans a list of security event dictionaries and flags any source IP address
    that has accumulated at least `threshold` LOGIN_FAILED events.

    Parameters:
        events (list): A list of event dictionaries.
        threshold (int): The minimum number of failed logins required to flag an IP.
                         Defaults to 3.

    Returns:
        list[dict]: A list of suspicious IP dictionaries, each containing:
                    - 'source_ip': The flagged IP address
                    - 'failed_attempts': The count of failed logins for that IP
    """
    # Step 1: Count failed login attempts per source IP address
    failed_counts = {}
    for event in events:
        if event.get("event_type") == "LOGIN_FAILED":
            ip = event.get("source_ip")
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

    # Step 2: Apply the threshold rule to identify suspicious IPs
    suspicious_ips = []
    for ip, count in failed_counts.items():
        if count >= threshold:
            suspicious_ips.append({
                "source_ip": ip,
                "failed_attempts": count,
            })

    return suspicious_ips


def detect_attack_sequences(events, time_window_seconds=300):
    """
    Detects correlated multi-stage attack sequences originating from the same IP address.

    The expected attack progression is:
      1. LOGIN_FAILED
      2. LOGIN_SUCCESS
      3. PRIVILEGE_ESCALATION
      4. INTERNAL_SERVER_ACCESS
      5. DATA_TRANSFER

    All steps must occur within `time_window_seconds` from the initial step.

    Parameters:
        events (list): List of security event dictionaries.
        time_window_seconds (int): Maximum allowed duration in seconds for the entire sequence.
                                   Defaults to 300 seconds (5 minutes).

    Returns:
        list[dict]: A list of detected attack sequence alerts.
    """
    # The ordered sequence of stages we are hunting for
    REQUIRED_STAGES = [
        "LOGIN_FAILED",
        "LOGIN_SUCCESS",
        "PRIVILEGE_ESCALATION",
        "INTERNAL_SERVER_ACCESS",
        "DATA_TRANSFER",
    ]

    # Step 1: Group all events by source_ip
    # This allows us to track the chronological story for each separate IP.
    events_by_ip = {}
    for event in events:
        ip = event.get("source_ip")
        if ip not in events_by_ip:
            events_by_ip[ip] = []
        events_by_ip[ip].append(event)

    detected_sequences = []

    # Step 2: Analyze each IP's timeline for the multi-stage progression
    for ip, ip_events in events_by_ip.items():
        i = 0
        while i < len(ip_events):
            event = ip_events[i]

            # We look for the start of an attack: LOGIN_FAILED
            if event.get("event_type") == REQUIRED_STAGES[0]:
                start_dt = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
                matched_events = [event]
                current_stage_idx = 1  # Next stage to look for is LOGIN_SUCCESS

                # Look forward at subsequent events from the same IP
                for j in range(i + 1, len(ip_events)):
                    next_event = ip_events[j]
                    next_dt = datetime.strptime(next_event["timestamp"], "%Y-%m-%d %H:%M:%S")

                    # Step 3: Check if this event falls outside the time window
                    time_diff = (next_dt - start_dt).total_seconds()
                    if time_diff > time_window_seconds:
                        # Time window expired; stop scanning this particular attempt
                        break

                    # Step 4: Check if this event matches the next stage in progression
                    if next_event.get("event_type") == REQUIRED_STAGES[current_stage_idx]:
                        matched_events.append(next_event)
                        current_stage_idx += 1

                        # If all 5 stages were found within the time window, alert!
                        if current_stage_idx == len(REQUIRED_STAGES):
                            detected_sequences.append({
                                "source_ip": ip,
                                "username": event.get("username"),
                                "detected_steps": [e["event_type"] for e in matched_events],
                                "start_time": matched_events[0]["timestamp"],
                                "end_time": matched_events[-1]["timestamp"],
                            })
                            # Fast-forward the search pointer past this completed sequence
                            i = j
                            break

            i += 1

    return detected_sequences
