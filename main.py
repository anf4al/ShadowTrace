import pandas as pd
from event_generator import generate_events
from detector import detect_failed_logins, detect_attack_sequences
from features import extract_features
from ml_detector import detect_anomalies, FEATURE_COLUMNS
from investigator import investigate_anomaly, generate_reasons

# Configuration for generating synthetic cybersecurity events
TOTAL_EVENTS = 1000
ATTACK_PROBABILITY = 0.01  # Realistic: ~1% chance per step, resulting in ~5-10 attack bursts among 1000 events

# Generate 1,000 events using the event generator module
events = generate_events(count=TOTAL_EVENTS, attack_chance=ATTACK_PROBABILITY)

# Print total number of generated events
print(f"Total events generated: {len(events)}")
print("=" * 60)

# Display a preview sample instead of printing all 1000 raw events
print("\n--- Sample of Generated Security Events (First 5) ---")
for index, event in enumerate(events[:5], start=1):
    print(
        f"{index:02d}. [{event['timestamp']}] "
        f"{event['event_type']:<24} "
        f"User: {event['username']:<8} "
        f"IP: {event['source_ip']:<15} "
        f"Server: {event['server']}"
    )

# Create a pandas DataFrame from the generated event dictionaries
df = pd.DataFrame(events)

# Print dataset summary metrics
print("\n" + "=" * 60)
print("--- Event Dataset Summary ---")
print(f"Time Range     : {df['timestamp'].min()} to {df['timestamp'].max()}")
print(f"Total Events   : {len(df)}")
print(f"Unique Users   : {df['username'].nunique()} {list(df['username'].unique())}")
print(f"Unique IPs     : {df['source_ip'].nunique()} {list(df['source_ip'].unique())}")
print(f"Unique Servers : {df['server'].nunique()} {list(df['server'].unique())}")

print("\n--- Event Distribution by Event Type ---")
print(df["event_type"].value_counts().to_string())

# Show frequency of events per source IP
print("\n--- Event Counts by Source IP ---")
ip_counts = df.groupby("source_ip").size()
print(ip_counts.to_string())

# Detection 1: Rule-based detector for repeated failed logins (Threshold >= 3)
print("\n" + "=" * 60)
print("--- Detection 1: Repeated Failed Logins (Threshold >= 3) ---")
suspicious_ips = detect_failed_logins(events, threshold=3)

if suspicious_ips:
    print(f"ALERT: Detected {len(suspicious_ips)} suspicious IP address(es) with >= 3 failed logins:\n")
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
    print(f"CRITICAL ALERT: Detected {len(attack_sequences)} correlated attack sequence(s)!\n")
    # Summary of sequences grouped by attacker IP
    seq_counts = pd.Series([seq["source_ip"] for seq in attack_sequences]).value_counts()
    print("Attack Sequences by Source IP:")
    for ip, count in seq_counts.items():
        print(f"  - {ip}: {count} attack sequences")

    # Display preview sample of first 3 incidents
    print(f"\nSample Incident Details (Showing First 3 of {len(attack_sequences)}):")
    for idx, alert in enumerate(attack_sequences[:3], start=1):
        print(f"  [INCIDENT #{idx}] Multi-Stage Attack Pattern Confirmed")
        print(f"    Attacker IP   : {alert['source_ip']}")
        print(f"    Victim User   : {alert['username']}")
        print(f"    Started At    : {alert['start_time']}")
        print(f"    Ended At      : {alert['end_time']}")
        print(f"    Attack Chain  : {' -> '.join(alert['detected_steps'])}\n")
    if len(attack_sequences) > 3:
        print(f"  ... and {len(attack_sequences) - 3} additional attack sequence(s) detected.")
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

# Step 2: Show exactly what the ML model sees
# Flow: features_df -> FEATURE_COLUMNS -> Matrix X -> Isolation Forest
print("\n[ML Data Flow: features_df -> FEATURE_COLUMNS -> Matrix X -> Isolation Forest]")
print(f"1. Feature Columns Passed to Model ({len(FEATURE_COLUMNS)} numerical features):")
for i, col in enumerate(FEATURE_COLUMNS, 1):
    print(f"   {i:02d}. {col}")

print("\n2. Numerical Feature Matrix X (Rows represent IPs, but source_ip string is excluded):")
# Create matrix X explicitly
X = features_df[FEATURE_COLUMNS]
print(X.to_string())

# Step 4: Run tuned Isolation Forest anomaly detection
ml_results_df = detect_anomalies(features_df)
print("\n3. Model Predictions & Anomaly Scores (1 = Normal, -1 = Anomaly):")
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
            f"| Failed Login Ratio: {row['failed_login_ratio']} "
            f"| Event Rate: {row['event_rate']}/s "
            f"| Failed Login Rate: {row['failed_login_rate']}/s "
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
        if len(report['event_types']) > 15:
            print(f"  Observed Event Types      : {report['event_types'][:15]} ... ({len(report['event_types'])} total events)")
        else:
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