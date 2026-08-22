from pathlib import Path
import sys, joblib, pandas as pd
from sklearn.ensemble import IsolationForest

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from preprocessing.preprocess import FEATURES

def train():
    data=pd.read_csv(ROOT/'dataset'/'activity_dataset.csv'); normal=data[data.label==0][FEATURES]
    pipeline=joblib.load(ROOT/'models'/'preprocessing_pipeline.pkl'); transformed=pipeline.transform(normal)
    detector=IsolationForest(n_estimators=180,contamination=.10,max_samples='auto',random_state=42,n_jobs=-1)
    detector.fit(transformed); joblib.dump(detector,ROOT/'models'/'anomaly_detector.pkl'); print(f"Isolation Forest fitted on {len(normal):,} normal records")
if __name__=='__main__': train()
