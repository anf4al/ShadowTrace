"""
investigator.py - Anomaly Investigation Module for ShadowTrace.

This module bridges the gap between machine-learning anomaly detection
and human triage. It pulls raw historical security events for any IP
flagged by the ML model and produces human-readable triage explanations.
"""


def investigate_anomaly(events, anomaly_row):
    """
    Investigates an anomalous IP address by retrieving all of its original
    security events and compiling an investigation summary.

    Parameters:
        events (list): The original list of security event dictionaries.
        anomaly_row (pd.Series or dict): The feature and prediction data for one anomalous IP.

    Returns:
        dict: An investigation summary containing behavioral statistics and
              the chronological list of observed event types for this IP.
    """
    # Step 1: Identify the source IP to investigate
    source_ip = anomaly_row["source_ip"]

    # Step 2: Filter original events belonging to this specific IP
    ip_events = []
    for event in events:
        if event.get("source_ip") == source_ip:
            ip_events.append(event)

    # Step 3: Extract the chronological sequence of event types observed for this IP
    event_types = []
    for event in ip_events:
        event_types.append(event.get("event_type"))

    # Step 4: Assemble and return the investigation report dictionary
    investigation_report = {
        "source_ip": source_ip,
        "failed_login_count": int(anomaly_row["failed_login_count"]),
        "successful_login_count": int(anomaly_row["successful_login_count"]),
        "privilege_escalation_count": int(anomaly_row["privilege_escalation_count"]),
        "server_access_count": int(anomaly_row["server_access_count"]),
        "data_transfer_count": int(anomaly_row["data_transfer_count"]),
        "total_event_count": int(anomaly_row["total_event_count"]),
        "activity_duration_seconds": int(anomaly_row["activity_duration_seconds"]),
        "event_types": event_types,
    }

    return investigation_report


def generate_reasons(investigation):
    """
    Analyzes an investigation dictionary and produces a list of human-readable
    explanations highlighting why the IP address warrants security attention.

    Parameters:
        investigation (dict): The dictionary returned by investigate_anomaly().

    Returns:
        list[str]: Human-readable reasons identifying suspicious behavioral factors.
    """
    reasons = []

    # Check 1: High failed login attempts (brute force or password guessing)
    if investigation["failed_login_count"] >= 3:
        reasons.append(
            f"High number of failed logins ({investigation['failed_login_count']} attempts), suggesting possible brute-force activity."
        )

    # Check 2: Privilege escalation
    if investigation["privilege_escalation_count"] >= 1:
        reasons.append(
            f"Privilege escalation detected ({investigation['privilege_escalation_count']} event(s)), indicating unauthorized privilege elevation."
        )

    # Check 3: Data transfer activity
    if investigation["data_transfer_count"] >= 1:
        reasons.append(
            f"Data transfer activity detected ({investigation['data_transfer_count']} event(s)), which could indicate data exfiltration."
        )

    # Check 4: Unusually high event volume
    if investigation["total_event_count"] >= 10:
        reasons.append(
            f"Unusually high event volume ({investigation['total_event_count']} total events) compared to normal traffic."
        )

    # Check 5: Unusually rapid activity rate
    duration = investigation["activity_duration_seconds"]
    total_events = investigation["total_event_count"]
    if duration > 0:
        event_rate = total_events / duration  # Events per second
        # A rate of >= 0.05 means an event occurs every 20 seconds or faster
        if event_rate >= 0.05:
            reasons.append(
                f"Unusually rapid activity: {total_events} events executed in only {duration}s (~{event_rate:.2f} events/sec)."
            )

    return reasons
