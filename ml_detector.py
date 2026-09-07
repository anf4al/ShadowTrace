"""
ml_detector.py - Machine Learning Anomaly Detection for ShadowTrace.

This module applies an unsupervised Isolation Forest model to numerical
behavioral features to identify unusual (anomalous) IP behaviors without
relying on hardcoded threshold rules.
"""

from sklearn.ensemble import IsolationForest

# Explicit list of numerical feature columns used as model input
FEATURE_COLUMNS = [
    "failed_login_count",
    "successful_login_count",
    "privilege_escalation_count",
    "server_access_count",
    "data_transfer_count",
    "total_event_count",
    "activity_duration_seconds",
]


def detect_anomalies(features_df, contamination=0.2, random_state=42):
    """
    Fits an Isolation Forest model to numerical behavioral features
    and assigns an anomaly prediction and anomaly score to each IP.

    Parameters:
        features_df (pd.DataFrame): DataFrame produced by extract_features().
        contamination (float): Expected proportion of outliers in the dataset (default: 0.2).
        random_state (int): Seed for reproducibility (default: 42).

    Returns:
        pd.DataFrame: A copy of features_df with two new columns:
                      - 'ml_prediction': -1 for anomaly, 1 for normal.
                      - 'anomaly_score': Continuous score from decision_function()
                                         (lower/negative values indicate greater abnormality).
    """
    # Step 1: Work on a clean copy so we don't mutate the original DataFrame
    result_df = features_df.copy()

    # Step 2: Extract only the numerical feature columns for model input (X)
    # The source_ip column is excluded because algorithms need numerical vectors.
    X = result_df[FEATURE_COLUMNS]

    # Step 3: Instantiate the Isolation Forest model
    # - contamination=0.2 indicates we expect roughly 20% of the observations to be unusual.
    # - random_state=42 ensures identical decision trees are built on each run.
    model = IsolationForest(contamination=contamination, random_state=random_state)

    # Step 4: Fit the model to learn the distribution of data points
    model.fit(X)

    # Step 5: Generate predictions (-1 = anomaly, 1 = normal)
    result_df["ml_prediction"] = model.predict(X)

    # Step 6: Compute continuous anomaly scores using decision_function()
    # Negative values denote anomalies; higher positive values denote typical normal behavior.
    result_df["anomaly_score"] = model.decision_function(X).round(4)

    return result_df
