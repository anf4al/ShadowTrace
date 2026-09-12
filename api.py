"""
api.py - FastAPI Application for ShadowTrace.

Serves as the API bridge between the ShadowTrace cybersecurity detection
pipeline and web/frontend interfaces.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from event_generator import generate_events
from detector import detect_attack_sequences
from features import extract_features
from ml_detector import detect_anomalies
from risk_scorer import calculate_risk_scores

app = FastAPI(
    title="ShadowTrace API",
    description="API for the ShadowTrace cybersecurity detection platform",
    version="1.0.0"
)

# Enable CORS for Vite frontend development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health_check():
    """
    Health check endpoint to verify API server status.
    """
    return {
        "status": "ok",
        "service": "ShadowTrace API"
    }


@app.get("/api/risks")
def get_risks():
    """
    Runs the ShadowTrace detection pipeline on synthetic events and returns
    the resulting IP risk assessments.
    """
    # 1. Generate synthetic security events
    events = generate_events(count=1000, attack_chance=0.01)

    # 2. Run rule-based attack sequence detection (time window: 300s)
    attack_sequences = detect_attack_sequences(events, time_window_seconds=300)

    # 3. Extract behavioral features grouped by source IP
    features_df = extract_features(events)

    # 4. Run Isolation Forest anomaly detection
    ml_results_df = detect_anomalies(features_df)

    # 5. Compute correlation-aware hybrid risk scores
    risk_assessments = calculate_risk_scores(ml_results_df, attack_sequences=attack_sequences)

    # 6. Return the clean JSON-serializable list of risk assessments
    return risk_assessments
