import pandas as pd
from event_generator import generate_events
from detector import detect_failed_logins, detect_attack_sequences
from features import extract_features
from ml_detector import detect_anomalies
from investigator import investigate_anomaly, generate_reasons

# Configuration for generating synthetic cybersecurity events
TOTAL_EVENTS = 50
ATTACK_PROBABILITY = 0.2  # 20% chance of triggering an attack sequence

# Generate events using the event generator module
events = generate_events(count=TOTAL_EVENTS, attack_chance=ATTACK_PROBABILITY)

# Print total number of generated events
print(f"Total events generated: {len(events)}")
print("=" * 60)

# Print generated events in a readable format
print("\n--- Generated Security Events ---")
for index, event in enumerate(events, start=1):
    print(
        f"{index:02d}. [{event['timestamp']}] "
        f"{event['event_type']:<24} "
        f"User: {event['username']:<8} "
        f"IP: {event['source_ip']:<15} "
        f"Server: {event['server']}"
    )

# Create a pandas DataFrame from the generated event dictionaries
df = pd.DataFrame(events)

# Print the DataFrame to verify compatibility with pandas
print("\n" + "=" * 60)
print("--- Pandas DataFrame Verification ---")
print(df)

# Show frequency of events per source IP
print("\n--- Event Counts by Source IP ---")
ip_counts = df.groupby("source_ip").size()
print(ip_counts)

# Detection 1: Rule-based detector for repeated failed logins (Threshold >= 3)
print("\n" + "=" * 60)
print("--- Detection 1: Repeated Failed Logins (Threshold >= 3) ---")
suspicious_ips = detect_failed_logins(events, threshold=3)

if suspicious_ips:
    print(f"ALERT: Detected {len(suspicious_ips)} suspicious IP address(es):\n")
    for alert in suspicious_ips:
        print(
            f"  [ALERT] Source IP: {alert['source_ip']} "
            f"exceeded threshold with {alert['failed_attempts']} failed login attempts."
        )
else:
    print("No IP addresses exceeded the failed login threshold.")

# Detection 2: Correlated multi-stage attack sequence detector (Time window: 300 seconds)
print("\n" + "=" * 60)
print("--- Detection 2: Correlated Multi-Stage Attacks (Time Window: 300s) ---")
attack_sequences = detect_attack_sequences(events, time_window_seconds=300)

if attack_sequences:
    print(f"CRITICAL ALERT: Detected {len(attack_sequences)} correlated attack sequence(s):\n")
    for idx, alert in enumerate(attack_sequences, start=1):
        print(f"  [INCIDENT #{idx}] Multi-Stage Attack Pattern Confirmed")
        print(f"    Attacker IP   : {alert['source_ip']}")
        print(f"    Victim User   : {alert['username']}")
        print(f"    Started At    : {alert['start_time']}")
        print(f"    Ended At      : {alert['end_time']}")
        print(f"    Attack Chain  : {' -> '.join(alert['detected_steps'])}\n")
else:
    print("No correlated attack sequences detected within the time window.")

# Feature Engineering for Machine Learning
print("\n" + "=" * 60)
print("--- Behavioral Features for Machine Learning ---")
features_df = extract_features(events)
print(features_df.to_string(index=False))

# Machine Learning Anomaly Detection (Isolation Forest)
print("\n" + "=" * 60)
print("--- Machine Learning Anomaly Detection ---")
ml_results_df = detect_anomalies(features_df)
print(ml_results_df.to_string(index=False))

# Clearly identify which IPs were classified as anomalies (-1)
anomalies = ml_results_df[ml_results_df["ml_prediction"] == -1]
print("\nIdentified Behavioral Anomalies (ml_prediction == -1):")
if not anomalies.empty:
    for _, row in anomalies.iterrows():
        print(
            f"  [ML ANOMALY] Source IP: {row['source_ip']} "
            f"| Anomaly Score: {row['anomaly_score']} "
            f"| Failed Logins: {row['failed_login_count']} "
            f"| Total Events: {row['total_event_count']} "
            f"| Duration: {row['activity_duration_seconds']}s"
        )
else:
    print("  No IP addresses were classified as anomalies.")

# Investigation of Detected Anomalies
print("\n" + "=" * 60)
print("--- Deep-Dive Investigation of Anomalous IPs ---")
if not anomalies.empty:
    for _, anomaly_row in anomalies.iterrows():
        report = investigate_anomaly(events, anomaly_row)
        print(f"\nInvestigation Report for IP: {report['source_ip']}")
        print(f"  Failed Login Count        : {report['failed_login_count']}")
        print(f"  Successful Login Count    : {report['successful_login_count']}")
        print(f"  Privilege Escalation Count: {report['privilege_escalation_count']}")
        print(f"  Server Access Count       : {report['server_access_count']}")
        print(f"  Data Transfer Count       : {report['data_transfer_count']}")
        print(f"  Total Event Count         : {report['total_event_count']}")
        print(f"  Activity Duration Seconds : {report['activity_duration_seconds']}s")
        print(f"  Observed Event Types      : {report['event_types']}")

        # Generate and print human-readable explanations
        reasons = generate_reasons(report)
        print("  Suspicious Factors Identified:")
        if reasons:
            for reason in reasons:
                print(f"    - {reason}")
        else:
            print("    - No specific threshold violations matched.")
else:
    print("No anomalous IPs found to investigate.")