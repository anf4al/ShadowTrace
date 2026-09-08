"""
event_generator.py - Synthetic Cybersecurity Event Generator for ShadowTrace.

This module generates synthetic security log events as Python dictionaries.
It can produce both normal day-to-day user activity and realistic,
suspicious multi-step attack sequences.
"""

from datetime import datetime, timedelta
import random

# Sample pools of users, IP addresses, and servers
USERS = ["alice", "bob", "charlie", "david", "emma"]

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.25",
    "192.168.1.42",
    "10.0.0.15",
]

ATTACKER_IPS = [
    "185.220.101.5",
    "194.26.29.112",
    "45.154.255.8",
]

SERVERS = [
    "auth-server-01",
    "file-server-02",
    "db-cluster-01",
    "app-server-01",
    "backup-vault-01",
]


def create_event(timestamp, event_type, username, source_ip, server):
    """
    Helper function to construct a single security event dictionary.
    """
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "server": server,
    }


def generate_normal_event(current_time):
    """
    Generates a single routine, benign security event.
    Advances the clock by a realistic normal interval (1 to 10 minutes).
    """
    user = random.choice(USERS)
    ip = random.choice(NORMAL_IPS)

    # Normal events are mostly successful logins and internal server access.
    # An occasional failed login simulates a normal user typo (approx 1% rate).
    event_type = random.choices(
        population=[
            "LOGIN_SUCCESS",
            "INTERNAL_SERVER_ACCESS",
            "DATA_TRANSFER",
            "LOGIN_FAILED",
        ],
        weights=[0.49, 0.40, 0.10, 0.01],
        k=1,
    )[0]

    # Pick a server suitable for the event type
    if event_type in ("LOGIN_SUCCESS", "LOGIN_FAILED"):
        server = "auth-server-01"
    elif event_type == "DATA_TRANSFER":
        server = "file-server-02"
    else:
        server = random.choice(["app-server-01", "file-server-02", "db-cluster-01"])

    event = create_event(current_time, event_type, user, ip, server)

    # Normal activity happens minutes apart
    next_time = current_time + timedelta(minutes=random.randint(1, 10))
    return event, next_time


def generate_suspicious_sequence(start_time):
    """
    Generates a sequence of related events simulating a targeted attack:
      1. Multiple rapid failed login attempts (brute-force or password guessing)
      2. A successful login from an external IP
      3. Privilege escalation
      4. Unauthorized access to a critical internal server (database or backup vault)
      5. Suspicious data transfer (data exfiltration)

    These events share the same attacker IP and victim user, and occur
    very close together in time (seconds to a minute apart).
    """
    events = []
    current_time = start_time

    attacker_ip = random.choice(ATTACKER_IPS)
    victim_user = random.choice(USERS)

    # Step 1: Rapid failed login attempts (2 to 4 attempts, 5-15 seconds apart)
    failed_attempts = random.randint(2, 4)
    for _ in range(failed_attempts):
        events.append(
            create_event(
                current_time,
                "LOGIN_FAILED",
                victim_user,
                attacker_ip,
                "auth-server-01",
            )
        )
        current_time += timedelta(seconds=random.randint(5, 15))

    # Step 2: Successful login (attacker gains access)
    events.append(
        create_event(
            current_time,
            "LOGIN_SUCCESS",
            victim_user,
            attacker_ip,
            "auth-server-01",
        )
    )
    current_time += timedelta(seconds=random.randint(10, 30))

    # Step 3: Privilege escalation (attacker elevates rights)
    events.append(
        create_event(
            current_time,
            "PRIVILEGE_ESCALATION",
            victim_user,
            attacker_ip,
            "auth-server-01",
        )
    )
    current_time += timedelta(seconds=random.randint(20, 60))

    # Step 4: Internal server access to high-value asset
    target_server = random.choice(["db-cluster-01", "backup-vault-01"])
    events.append(
        create_event(
            current_time,
            "INTERNAL_SERVER_ACCESS",
            victim_user,
            attacker_ip,
            target_server,
        )
    )
    current_time += timedelta(seconds=random.randint(15, 45))

    # Step 5: Data transfer (exfiltration of sensitive data)
    events.append(
        create_event(
            current_time,
            "DATA_TRANSFER",
            victim_user,
            attacker_ip,
            target_server,
        )
    )
    # Move time forward slightly after sequence finishes
    next_time = current_time + timedelta(minutes=random.randint(2, 5))

    return events, next_time


def generate_events(count=1000, attack_chance=0.01, start_time=None):
    """
    Generates a list of synthetic security events with a realistic normal-to-attack ratio.

    Parameters:
      count (int): Total number of events to generate (default: 1000).
      attack_chance (float): Probability (0.0 to 1.0) of starting an attack sequence.
                             Defaults to 0.01 (1%), providing realistic, low-frequency attack bursts.
      start_time (datetime, optional): Starting timestamp for the simulation.

    Returns:
      list: A list of event dictionaries sorted chronologically.
    """
    if start_time is None:
        start_time = datetime(2026, 9, 6, 8, 0, 0)

    events = []
    current_time = start_time

    while len(events) < count:
        remaining = count - len(events)

        # Trigger a suspicious sequence if probability matches and there is room for full sequence (up to 8 events)
        if remaining >= 8 and random.random() < attack_chance:
            attack_events, current_time = generate_suspicious_sequence(current_time)
            events.extend(attack_events)
        else:
            normal_event, current_time = generate_normal_event(current_time)
            events.append(normal_event)

    # Trim to exact requested count if needed
    return events[:count]


if __name__ == "__main__":
    # Example standalone run for quick verification
    sample_data = generate_events(count=10)
    print(f"Generated {len(sample_data)} sample events:\n")
    for event in sample_data:
        print(event)
