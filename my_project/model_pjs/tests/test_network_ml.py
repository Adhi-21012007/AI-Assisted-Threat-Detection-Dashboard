import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from model_pjs.network_ml import train_unsw_nb15 as network


class NetworkMlTests(unittest.TestCase):
    def test_unsw_preprocessing_training_and_metrics(self):
        # Small labelled fixture validates the pipeline mechanics; it is not an
        # evaluation claim for UNSW-NB15 itself.
        rows = []
        for label, offset in (("Normal", 0), ("Exploits", 10), ("Fuzzers", 20)):
            for index in range(10):
                row = {f"feature_{n}": offset + index + n for n in range(20)}
                row.update(proto="tcp" if index % 2 else "udp", attack_cat=label, id=len(rows) + 1)
                rows.append(row)
        with tempfile.TemporaryDirectory() as folder:
            csv_path = Path(folder) / "unsw_fixture.csv"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            with patch.object(network, "OUTPUT", Path(folder) / "outputs"), patch.object(network, "MODEL", Path(folder) / "models"):
                metrics = network.train(csv_path)
                self.assertIn("classification_report", metrics)
                self.assertIn("weighted_recall", metrics)
                saved = json.loads((Path(folder) / "outputs" / "unsw_network_metrics.json").read_text())
                self.assertEqual(saved["label_column"], "attack_cat")
                self.assertTrue((Path(folder) / "models" / "unsw_network_risk_pipeline.pkl").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
