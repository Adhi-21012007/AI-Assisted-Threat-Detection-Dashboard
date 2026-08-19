from pathlib import Path
import json, sys
import joblib, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from preprocessing.preprocess import FEATURES, build_pipeline

def train():
    data=pd.read_csv(ROOT/'dataset'/'activity_dataset.csv'); X=data[FEATURES]; y=data['label']
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    pipeline=build_pipeline(); X_train_t=pipeline.fit_transform(X_train); X_test_t=pipeline.transform(X_test)
    model=RandomForestClassifier(n_estimators=220,max_depth=16,min_samples_leaf=3,class_weight='balanced_subsample',random_state=42,n_jobs=-1)
    model.fit(X_train_t,y_train); prediction=model.predict(X_test_t)
    precision,recall,f1,_=precision_recall_fscore_support(y_test,prediction,average='weighted',zero_division=0)
    metrics={'accuracy':round(float(accuracy_score(y_test,prediction)),4),'precision_weighted':round(float(precision),4),'recall_weighted':round(float(recall),4),'f1_weighted':round(float(f1),4),'test_size':int(len(y_test))}
    models=ROOT/'models';models.mkdir(exist_ok=True); joblib.dump(model,models/'threat_classifier.pkl');joblib.dump(pipeline,models/'preprocessing_pipeline.pkl')
    (ROOT/'outputs'/'rf_metrics.json').write_text(json.dumps(metrics,indent=2)); pd.DataFrame({'actual':y_test,'predicted':prediction}).to_csv(ROOT/'outputs'/'rf_test_predictions.csv',index=False)
    # Persist metadata needed by inference explanations.
    names=pipeline.get_feature_names_out().tolist(); importance=dict(sorted(zip(names,model.feature_importances_),key=lambda x:x[1],reverse=True))
    (models/'model_metadata.json').write_text(json.dumps({'features':FEATURES,'rf_metrics':metrics,'feature_importance':importance},indent=2))
    print(metrics); return metrics
if __name__=='__main__': train()
