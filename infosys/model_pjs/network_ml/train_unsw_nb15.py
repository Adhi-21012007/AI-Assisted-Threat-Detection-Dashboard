"""Train a reproducible network-risk model from an analyst-supplied UNSW-NB15 CSV.

This intentionally stays separate from model_pjs/dataset/activity_dataset.csv:
employee activity and network packets use incompatible feature spaces.
"""
import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "network_ml" / "outputs"
MODEL = ROOT / "network_ml" / "models"


def _label_column(frame):
    for column in ("attack_cat", "label", "Label", "class"):
        if column in frame.columns:
            return column
    raise ValueError("UNSW-NB15 CSV needs attack_cat or label column.")


def train(csv_path):
    frame = pd.read_csv(csv_path)
    label = _label_column(frame)
    target = frame[label].fillna("Normal").astype(str)
    # id is an identifier, not a traffic behaviour feature.
    features = frame.drop(columns=[label] + [x for x in ("id", "Id") if x in frame.columns])
    if len(features) < 20 or target.nunique() < 2:
        raise ValueError("CSV does not appear to contain a usable labelled UNSW-NB15 dataset.")
    categorical = list(features.select_dtypes(include=["object", "category", "bool"]).columns)
    numeric = [x for x in features.columns if x not in categorical]
    preprocess = ColumnTransformer([
        ("numeric", Pipeline([("impute", SimpleImputer(strategy="median"))]), numeric),
        ("categorical", Pipeline([("impute", SimpleImputer(strategy="most_frequent")), ("encode", OneHotEncoder(handle_unknown="ignore"))]), categorical),
    ])
    x_train, x_test, y_train, y_test = train_test_split(features, target, test_size=.2, random_state=42, stratify=target)
    model = Pipeline([("preprocess", preprocess), ("classifier", RandomForestClassifier(n_estimators=250, class_weight="balanced_subsample", random_state=42, n_jobs=-1))])
    model.fit(x_train, y_train)
    predicted = model.predict(x_test)
    metrics = {"dataset": str(Path(csv_path).resolve()), "rows": int(len(frame)), "label_column": label,
               "accuracy": round(float(accuracy_score(y_test, predicted)), 4),
               "classification_report": classification_report(y_test, predicted, output_dict=True, zero_division=0),
               "confusion_matrix_labels": sorted(target.unique()),
               "confusion_matrix": confusion_matrix(y_test, predicted, labels=sorted(target.unique())).tolist()}
    precision, recall, f1, support = precision_recall_fscore_support(y_test, predicted, average="weighted", zero_division=0)
    metrics.update(weighted_precision=round(float(precision), 4), weighted_recall=round(float(recall), 4), weighted_f1=round(float(f1), 4), support=int(len(y_test)))
    if target.nunique() == 2:
        scores = model.predict_proba(x_test)[:, 1]
        metrics["roc_auc"] = round(float(roc_auc_score(y_test, scores)), 4)
    OUTPUT.mkdir(parents=True, exist_ok=True); MODEL.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL / "unsw_network_risk_pipeline.pkl")
    (OUTPUT / "unsw_network_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the separate UNSW-NB15 network-risk model.")
    parser.add_argument("csv", help="Path to analyst-provided UNSW-NB15 CSV")
    args = parser.parse_args()
    print(json.dumps(train(args.csv), indent=2))
