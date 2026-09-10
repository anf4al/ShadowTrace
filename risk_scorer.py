"""
risk_scorer.py - Hybrid Risk-Scoring Engine for ShadowTrace.

This module combines unsupervised machine-learning anomaly predictions
with rule-based behavioral indicators to produce a unified, explainable
risk score (0 to 100) and operational threat level for each source IP.
"""

# Risk weight configuration (Total maximum possible = 100)
WEIGHT_ML_ANOMALY = 40
WEIGHT_FAILED_LOGINS = 15
WEIGHT_PRIVILEGE_ESCALATION = 20
WEIGHT_DATA_TRANSFER = 20
WEIGHT_RAPID_ACTIVITY = 5

# Threshold constants
FAILED_LOGIN_THRESHOLD = 3
RAPID_ACTIVITY_THRESHOLD = 0.05  # Events per second (same as investigator.py)


def get_risk_level(score):
    """
    Maps a numerical risk score (0-100) to an operational threat category:
      0–29   -> LOW
      30–59  -> MEDIUM
      60–79  -> HIGH
      80–100 -> CRITICAL
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_ip_risk(ip_data):
    """
    Calculates the hybrid risk score, risk level, and contributing reasons for a single IP.

    Parameters:
        ip_data (pd.Series or dict): Row containing ML prediction and behavioral features.

    Returns:
        dict: Assessment containing:
              - 'source_ip': The IP address
              - 'risk_score': Total score (0 to 100)
              - 'risk_level': 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'
              - 'reasons': List of human-readable explanations for awarded points
    """
    source_ip = ip_data["source_ip"]
    score = 0
    reasons = []

    # Signal 1: Isolation Forest Anomaly Detection (+40 points)
    # -1 represents an anomaly in scikit-learn Isolation Forest convention
    if ip_data.get("ml_prediction") == -1:
        score += WEIGHT_ML_ANOMALY
        reasons.append("Isolation Forest detected anomalous behavior")

    # Signal 2: Failed Login Pattern (+15 points)
    failed_logins = int(ip_data.get("failed_login_count", 0))
    if failed_logins >= FAILED_LOGIN_THRESHOLD:
        score += WEIGHT_FAILED_LOGINS
        reasons.append("Multiple failed login attempts detected")

    # Signal 3: Privilege Escalation Detected (+20 points)
    priv_esc = int(ip_data.get("privilege_escalation_count", 0))
    if priv_esc >= 1:
        score += WEIGHT_PRIVILEGE_ESCALATION
        reasons.append("Privilege escalation detected")

    # Signal 4: Data Transfer Detected (+20 points)
    data_transfer = int(ip_data.get("data_transfer_count", 0))
    if data_transfer >= 1:
        score += WEIGHT_DATA_TRANSFER
        reasons.append("Data transfer detected")

    # Signal 5: Rapid Activity Burst (+5 points)
    event_rate = float(ip_data.get("event_rate", 0.0))
    if event_rate >= RAPID_ACTIVITY_THRESHOLD:
        score += WEIGHT_RAPID_ACTIVITY
        reasons.append("Rapid activity detected")

    # Cap score at 100 as a strict upper bound guarantee
    risk_score = min(score, 100)
    risk_level = get_risk_level(risk_score)

    return {
        "source_ip": source_ip,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
    }


def calculate_risk_scores(ml_results_df):
    """
    Calculates hybrid risk scores for all IPs in the results DataFrame.

    Parameters:
        ml_results_df (pd.DataFrame): DataFrame containing behavioral features and ml_prediction.

    Returns:
        list[dict]: List of risk assessment dictionaries for each IP, sorted by risk score descending.
    """
    assessments = []
    for _, row in ml_results_df.iterrows():
        assessment = calculate_ip_risk(row)
        assessments.append(assessment)

    # Sort descending so the most critical threats appear at the top
    assessments.sort(key=lambda x: x["risk_score"], reverse=True)
    return assessments
