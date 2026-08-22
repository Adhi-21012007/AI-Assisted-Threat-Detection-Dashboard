# Synthetic security behaviour dataset

`activity_dataset.csv` contains 30,000 reproducible, labelled activity windows. A record represents aggregated user behaviour over a short observation interval, not an individual raw log line. Labels are 0 Normal, 1 Suspicious, and 2 Threat. The generator encodes realistic correlations (for example, brute force increases failed authentication attempts and login frequency; exfiltration increases downloads, sensitive access, and after-hours activity).

It is a development dataset only. It cannot establish real-world detection performance and must be replaced or augmented with reviewed production telemetry before operational use.
