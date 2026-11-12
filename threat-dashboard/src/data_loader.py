"""
data_loader.py - Member A (ML)
Loads NSL-KDD dataset files, maps 41 feature headers, and creates binary attack indicators.
"""
import pandas as pd
import numpy as np

NSL_KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

ATTACK_CATEGORY_MAP = {
    # DoS
    'apache2': 'DoS', 'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS',
    'mailbomb': 'DoS', 'pod': 'DoS', 'processtable': 'DoS', 'smurf': 'DoS',
    'teardrop': 'DoS', 'udpstorm': 'DoS',
    # Probe
    'ipsweep': 'Probe', 'mscan': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'saint': 'Probe', 'satan': 'Probe',
    # R2L
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'httptunnel': 'R2L', 'imap': 'R2L',
    'multihop': 'R2L', 'named': 'R2L', 'phf': 'R2L', 'sendmail': 'R2L',
    'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L',
    'warezmaster': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'ps': 'U2R',
    'rootkit': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
    # Normal
    'normal': 'Normal'
}

def load_nsl_kdd(path: str) -> pd.DataFrame:
    """
    Loads raw NSL-KDD dataset without header, assigns columns,
    creates is_attack (0 or 1), and maps attack_category.
    """
    df = pd.read_csv(path, names=NSL_KDD_COLUMNS, header=None)
    df['is_attack'] = (df['label'] != 'normal').astype(int)
    df['attack_category'] = df['label'].map(lambda x: ATTACK_CATEGORY_MAP.get(x, 'DoS' if x != 'normal' else 'Normal'))
    df = df.drop(columns=['difficulty'], errors='ignore')
    return df
