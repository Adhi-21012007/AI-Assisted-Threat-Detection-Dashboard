"""Generate a reproducible, behaviourally coherent synthetic security dataset."""
from pathlib import Path
import numpy as np
import pandas as pd

SEED = 42
N_RECORDS = 30_000
OUT = Path(__file__).with_name("activity_dataset.csv")

DEPARTMENTS = ["Technology", "Operations", "People", "Finance", "Security"]
TEAMS = ["Product Engineering", "Customer Operations", "People Experience", "Finance Ops", "Cyber Security"]

def _base_record(rng, role, department, team):
    hour = int(np.clip(rng.normal(10.5, 2.1), 6, 19))
    weekend = int(rng.random() < .08)
    hour = int(rng.integers(8, 16)) if weekend else hour
    login_count = max(1, int(rng.poisson(1.5)))
    failed = int(rng.binomial(login_count + 1, .035))
    file_access = max(0, int(rng.poisson(7 if role == "Employee" else 11)))
    return dict(
        user_id=f"{'ADM' if role == 'Admin' else 'EMP'}{rng.integers(1, 1501):04d}", user_role=role,
        department=department, team=team, account_age_days=int(rng.integers(30, 2400)),
        login_count=login_count, failed_login_count=failed, successful_login_count=max(0, login_count-failed),
        failed_login_ratio=round(failed / max(login_count, 1), 4), login_frequency=round(login_count / rng.uniform(.5, 2.5), 3),
        session_duration=round(max(4, rng.normal(310, 100)), 2), concurrent_sessions=int(rng.choice([1, 1, 1, 2], p=[.55,.2,.15,.1])),
        hour=hour, day_of_week=int(rng.integers(0, 7)), weekend=weekend, unusual_hour=int(hour < 7 or hour > 20), working_hours=int(8 <= hour <= 18 and not weekend),
        activities_per_hour=round(max(.2, rng.normal(7, 2.5)), 2), activities_per_day=round(max(1, rng.normal(35, 11)), 2),
        file_access_count=file_access, file_upload_count=max(0, int(rng.poisson(1))), file_download_count=max(0, int(rng.poisson(2))),
        ticket_count=int(rng.poisson(.12)), task_activity_count=max(0, int(rng.poisson(3))), notification_activity_count=max(0, int(rng.poisson(2))),
        unique_ip_count=1, ip_change_frequency=0, new_ip_indicator=0, sensitive_file_access=int(rng.random() < .08),
        privilege_change=0, unusual_resource_access=0, deviation_from_user_baseline=round(abs(rng.normal(.45,.22)),3),
        deviation_from_team_baseline=round(abs(rng.normal(.40,.20)),3), activity_spike=0, login_pattern_deviation=round(abs(rng.normal(.35,.18)),3),
    )

def _apply_suspicious(row, rng):
    scenario = rng.choice(["Suspicious Login", "Abnormal Behaviour", "Account Takeover"], p=[.5,.3,.2])
    row.update(hour=int(rng.choice([0,1,2,3,4,21,22,23])), unusual_hour=1, working_hours=0,
               failed_login_count=int(rng.integers(3, 8)), login_count=int(rng.integers(4, 10)),
               unique_ip_count=int(rng.integers(2, 4)), ip_change_frequency=round(rng.uniform(1,4),2), new_ip_indicator=1,
               activities_per_hour=round(rng.uniform(12,26),2), activity_spike=1,
               deviation_from_user_baseline=round(rng.uniform(1.4,2.8),3), deviation_from_team_baseline=round(rng.uniform(1.2,2.5),3),
               login_pattern_deviation=round(rng.uniform(1.3,2.7),3))
    row["successful_login_count"] = max(0, row["login_count"] - row["failed_login_count"])
    row["failed_login_ratio"] = round(row["failed_login_count"] / row["login_count"], 4)
    return scenario

def _apply_threat(row, rng):
    scenario = rng.choice(["Brute Force", "Credential Attack", "Account Takeover", "Insider Threat", "Possible Data Exfiltration", "Privilege Abuse", "Automated Activity"], p=[.26,.13,.13,.12,.18,.08,.10])
    row.update(hour=int(rng.choice([0,1,2,3,4,22,23])), unusual_hour=1, working_hours=0, activity_spike=1,
               unique_ip_count=int(rng.integers(3, 8)), ip_change_frequency=round(rng.uniform(3,12),2), new_ip_indicator=1,
               deviation_from_user_baseline=round(rng.uniform(2.4,6.0),3), deviation_from_team_baseline=round(rng.uniform(2.0,5.5),3),
               login_pattern_deviation=round(rng.uniform(2.2,5.8),3), concurrent_sessions=int(rng.integers(2, 7)))
    if scenario == "Brute Force":
        row.update(failed_login_count=int(rng.integers(18, 45)), login_count=int(rng.integers(20, 55)), login_frequency=round(rng.uniform(22,75),2), activities_per_hour=round(rng.uniform(30,90),2))
    elif scenario == "Possible Data Exfiltration":
        row.update(file_access_count=int(rng.integers(120,450)), file_download_count=int(rng.integers(80,350)), file_upload_count=int(rng.integers(10,80)), sensitive_file_access=1, activities_per_hour=round(rng.uniform(25,70),2))
    elif scenario == "Privilege Abuse":
        row.update(privilege_change=1, sensitive_file_access=1, unusual_resource_access=1, file_access_count=int(rng.integers(40,160)))
    elif scenario == "Insider Threat":
        row.update(sensitive_file_access=1, unusual_resource_access=1, file_download_count=int(rng.integers(30,150)), ticket_count=int(rng.integers(1,5)))
    elif scenario == "Automated Activity":
        row.update(login_count=int(rng.integers(18,50)), login_frequency=round(rng.uniform(25,80),2), activities_per_hour=round(rng.uniform(45,120),2), task_activity_count=int(rng.integers(15,60)))
    else:
        row.update(failed_login_count=int(rng.integers(8,22)), login_count=int(rng.integers(9,28)), activities_per_hour=round(rng.uniform(22,60),2))
    row["successful_login_count"] = max(0, row["login_count"] - row["failed_login_count"])
    row["failed_login_ratio"] = round(row["failed_login_count"] / max(row["login_count"],1), 4)
    return scenario

def generate_dataset(n_records=N_RECORDS, seed=SEED):
    rng = np.random.default_rng(seed); records=[]
    labels = rng.choice([0,1,2], size=n_records, p=[.70,.19,.11])
    for label in labels:
        role = rng.choice(["Employee","Admin"], p=[.91,.09]); idx=int(rng.integers(0,len(DEPARTMENTS)))
        row=_base_record(rng,role,DEPARTMENTS[idx],TEAMS[idx])
        if label == 0: threat_type="Normal"
        elif label == 1: threat_type=_apply_suspicious(row,rng)
        else: threat_type=_apply_threat(row,rng)
        # Mild label-preserving noise prevents a perfectly separable toy dataset.
        if rng.random() < .035: row["activities_per_hour"] *= rng.uniform(.72,1.3)
        row["label"]=int(label); row["threat_type"]=threat_type; records.append(row)
    data = pd.DataFrame(records)
    # Security labels are often imperfect: a small, deterministic review-noise
    # fraction prevents unrealistically perfect synthetic evaluation results.
    ambiguous = rng.random(len(data)) < .055
    for index in data.index[ambiguous]:
        current = int(data.at[index, "label"])
        if current == 0:
            data.at[index, "label"] = 1; data.at[index, "threat_type"] = "Abnormal Behaviour"
        elif current == 2:
            data.at[index, "label"] = 1; data.at[index, "threat_type"] = "Suspicious Behaviour"
        else:
            data.at[index, "label"] = 0; data.at[index, "threat_type"] = "Normal"
    return data

if __name__ == "__main__":
    data=generate_dataset(); data.to_csv(OUT,index=False); print(f"Wrote {len(data):,} records to {OUT}")
