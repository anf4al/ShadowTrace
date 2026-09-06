import pandas as pd
from event_generator import generate_events

# 1 & 2. Configuration for generating synthetic cybersecurity events
TOTAL_EVENTS = 50
ATTACK_PROBABILITY = 0.2  # 20% chance of triggering an attack sequence

# Generate the events using our event generator module
events = generate_events(count=TOTAL_EVENTS, attack_chance=ATTACK_PROBABILITY)

# 4. Print the total number of generated events
print(f"Total events generated: {len(events)}")
print("=" * 60)

# 5. Print the generated events in a readable format
print("\n--- Generated Security Events ---")
for index, event in enumerate(events, start=1):
    print(
        f"{index:02d}. [{event['timestamp']}] "
        f"{event['event_type']:<24} "
        f"User: {event['username']:<8} "
        f"IP: {event['source_ip']:<15} "
        f"Server: {event['server']}"
    )

# 6. Create a pandas DataFrame from the generated event dictionaries
df = pd.DataFrame(events)

# 7. Print the DataFrame to verify it works with pandas
print("\n" + "=" * 60)
print("--- Pandas DataFrame Verification ---")
print(df)

# Show frequency of events per source IP (from the original ShadowTrace analysis)
print("\n--- Event Counts by Source IP ---")
ip_counts = df.groupby("source_ip").size()
print(ip_counts)