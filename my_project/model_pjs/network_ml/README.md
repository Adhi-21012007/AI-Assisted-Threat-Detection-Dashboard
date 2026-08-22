# UNSW-NB15 network ML

This module is intentionally separate from the existing employee-behaviour Random Forest and Isolation Forest. It accepts a labelled UNSW-NB15 CSV provided by the analyst, trains a reproducible Random Forest pipeline, and writes the model plus evaluation results.

No UNSW-NB15 data or scores are bundled, so the platform never claims network-model evaluation without a real dataset.

```powershell
python -m model_pjs.network_ml.train_unsw_nb15 C:\approved-data\UNSW_NB15_training-set.csv
```

Outputs:

- `model_pjs/network_ml/models/unsw_network_risk_pipeline.pkl`
- `model_pjs/network_ml/outputs/unsw_network_metrics.json`

The metrics file includes accuracy, weighted precision/recall/F1, a class-wise classification report, confusion matrix, and ROC-AUC only for a binary-labelled dataset. Select and document a model based on attack-class recall, not accuracy alone.
