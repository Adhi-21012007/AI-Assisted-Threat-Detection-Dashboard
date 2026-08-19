"""Inference entry point. Load once in a service; do not retrain per activity."""
from pathlib import Path
import json,sys,uuid
from datetime import datetime,timezone
import joblib
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from detection.feature_engineering import build_feature_row
from detection.risk_scoring import LABELS,calculate_risk,supporting_reasons,infer_threat_type

class ThreatPredictor:
    def __init__(self, model_dir=None):
        directory=Path(model_dir or ROOT/'models');self.pipeline=joblib.load(directory/'preprocessing_pipeline.pkl');self.classifier=joblib.load(directory/'threat_classifier.pkl');self.anomaly_detector=joblib.load(directory/'anomaly_detector.pkl')
    def predict_activity(self, activity_data):
        raw=dict(activity_data); features=build_feature_row(raw); matrix=self.pipeline.transform(features); prediction=int(self.classifier.predict(matrix)[0]); probabilities=self.classifier.predict_proba(matrix)[0]; confidence=float(probabilities[prediction]); anomaly=bool(self.anomaly_detector.predict(matrix)[0]==-1)
        # An anomaly can raise a low-confidence Normal classification to Suspicious.
        if prediction==0 and anomaly and confidence<.90: prediction=1
        risk,severity=calculate_risk(prediction,confidence,anomaly,raw);now=datetime.now(timezone.utc).isoformat()
        return {'event_id':str(uuid.uuid4()),'user_id':raw.get('user_id','UNKNOWN'),'timestamp':raw.get('timestamp',now),'prediction':LABELS[prediction],'threat_type':infer_threat_type(prediction,raw,anomaly),'confidence':round(confidence,4),'risk_score':risk,'severity':severity,'reasons':supporting_reasons(raw,prediction,anomaly),'source':raw.get('source','Activity Provider'),'processed_at':now,'anomaly_detected':anomaly}

_predictor=None
def predict_activity(activity_data):
    global _predictor
    if _predictor is None:_predictor=ThreatPredictor()
    return _predictor.predict_activity(activity_data)

if __name__=='__main__':
    payload=json.loads((ROOT/'sample'/'sample_activity.json').read_text());print(json.dumps(predict_activity(payload),indent=2))
