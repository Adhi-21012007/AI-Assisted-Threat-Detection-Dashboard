from pathlib import Path
import json,sys,joblib,pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay,classification_report
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from preprocessing.preprocess import FEATURES

def evaluate():
 data=pd.read_csv(ROOT/'dataset'/'activity_dataset.csv');pred=pd.read_csv(ROOT/'outputs'/'rf_test_predictions.csv'); labels=['Normal','Suspicious','Threat']
 fig,ax=plt.subplots(figsize=(5,4));ConfusionMatrixDisplay.from_predictions(pred.actual,pred.predicted,display_labels=labels,cmap='Blues',ax=ax,colorbar=False);ax.set_title('Random Forest confusion matrix');fig.tight_layout();fig.savefig(ROOT/'outputs'/'confusion_matrix.png',dpi=160);plt.close(fig)
 fig,ax=plt.subplots(figsize=(6,4));data.threat_type.value_counts().plot(kind='bar',ax=ax,color='#8e7dff');ax.set_title('Synthetic threat-type distribution');ax.set_ylabel('Records');ax.tick_params(axis='x',rotation=35);fig.tight_layout();fig.savefig(ROOT/'outputs'/'threat_distribution.png',dpi=160);plt.close(fig)
 model=joblib.load(ROOT/'models'/'threat_classifier.pkl');pipe=joblib.load(ROOT/'models'/'preprocessing_pipeline.pkl');names=pipe.get_feature_names_out(); top=sorted(zip(names,model.feature_importances_),key=lambda z:z[1],reverse=True)[:15]
 fig,ax=plt.subplots(figsize=(8,5));ax.barh([x[0] for x in top][::-1],[x[1] for x in top][::-1],color='#35c5bb');ax.set_title('Random Forest feature importance');fig.tight_layout();fig.savefig(ROOT/'outputs'/'feature_importance.png',dpi=160);plt.close(fig)
 report=classification_report(pred.actual,pred.predicted,target_names=labels,output_dict=True,zero_division=0);(ROOT/'outputs'/'classification_report.json').write_text(json.dumps(report,indent=2));return report
if __name__=='__main__':evaluate()
