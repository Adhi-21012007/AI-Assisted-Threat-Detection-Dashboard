"""Reproducible development workflow: dataset → train → evaluate → test → package."""
from pathlib import Path
import sys,zipfile
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from dataset.generate_dataset import generate_dataset
from training.train_random_forest import train as train_rf
from training.train_isolation_forest import train as train_if
from training.compare_models import compare
from training.evaluate_models import evaluate
from tests.test_cases import run as run_tests

def package():
    archive=ROOT/'final_threat_detection_model.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for folder in ['models','detection','data_source','sample']:
            for file in (ROOT/folder).rglob('*'):
                if file.is_file() and '__pycache__' not in file.parts and file.suffix != '.pyc': z.write(file,file.relative_to(ROOT))
        for file in ['requirements.txt','README.md']:
            z.write(ROOT/file,file)
    return archive

def main():
    dataset=generate_dataset();dataset.to_csv(ROOT/'dataset'/'activity_dataset.csv',index=False);print(f'Dataset: {len(dataset):,} rows')
    train_rf();train_if();compare();evaluate();run_tests();print('Package created:',package().name)
if __name__=='__main__':main()
