LABELS={0:'Normal',1:'Suspicious',2:'Threat'}

def calculate_risk(prediction, confidence, anomaly, raw):
    # Model confidence supplies the base; observed risk indicators are bounded
    # evidence modifiers rather than a second hard-coded detector.
    base={0:8,1:42,2:72}[int(prediction)] + confidence*16
    modifiers=min(16, raw.get('failed_login_count',0)*.35)+min(10,raw.get('file_download_count',0)/25)+ (7 if anomaly else 0) + (4 if raw.get('new_ip_indicator',0) else 0) + (4 if raw.get('privilege_change',0) else 0)
    score=int(round(min(100,base+modifiers)))
    severity='Low' if score<=30 else 'Medium' if score<=70 else 'High' if score<=90 else 'Critical'
    return score,severity

def supporting_reasons(raw, prediction, anomaly):
    reasons=[]
    if raw.get('failed_login_count',0)>=3: reasons.append(f"{raw['failed_login_count']} failed login attempts")
    if raw.get('unusual_hour') or raw.get('hour',9)<7 or raw.get('hour',9)>20: reasons.append('Activity occurred outside normal working hours')
    if raw.get('unique_ip_count',1)>1 or raw.get('new_ip_indicator'): reasons.append('New or multiple IP addresses observed')
    if raw.get('activity_spike') or raw.get('activities_per_hour',0)>20: reasons.append('Activity volume is above the expected baseline')
    if raw.get('file_download_count',0)>40: reasons.append('High file download volume')
    if raw.get('sensitive_file_access'): reasons.append('Sensitive resource access observed')
    if raw.get('privilege_change'): reasons.append('Privilege change activity observed')
    if anomaly: reasons.append('Isolation Forest marked this behaviour as anomalous')
    return reasons or ['Behaviour is consistent with the learned normal baseline']

def infer_threat_type(prediction, raw, anomaly):
    if int(prediction)==0 and not anomaly:return 'Normal Behaviour'
    if raw.get('failed_login_count',0)>=15:return 'Brute Force Attack'
    if raw.get('file_download_count',0)>=60 and raw.get('sensitive_file_access'):return 'Possible Data Exfiltration'
    if raw.get('privilege_change'):return 'Privilege Abuse'
    if raw.get('new_ip_indicator') and raw.get('unusual_hour'):return 'Account Takeover' if int(prediction)==2 else 'Suspicious Login'
    if raw.get('activities_per_hour',0)>=40:return 'Automated Activity'
    return 'Suspicious Behaviour' if int(prediction)==1 or anomaly else 'Abnormal Behaviour'
