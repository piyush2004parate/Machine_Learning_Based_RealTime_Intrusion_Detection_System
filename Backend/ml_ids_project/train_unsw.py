import os
import json
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.feature_selection import mutual_info_classif
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
import joblib

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def load_unsw(csv_path: Path) -> pd.DataFrame:
    return pd.read_csv(csv_path)

def build_feature_sets(df: pd.DataFrame):
    features = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload',
                'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb',
                'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
                'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
                'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports']
    non_numeric = ['is_sm_ips_ports', 'is_ftp_login']
    numeric_features = list(set(features) - set(non_numeric))
    non_log = ['sttl', 'dttl', 'swin', 'dwin', 'trans_depth', 'ct_state_ttl', 'ct_flw_http_mthd']
    return features, numeric_features, non_log, non_numeric

def log_transform(df: pd.DataFrame, numeric_features, non_log):
    df_logs = np.log10(df[list(set(numeric_features) - set(non_log))] + 1)
    df_numeric = pd.concat([df_logs, df[non_log]], axis=1)
    return df_numeric

def preprocess(df: pd.DataFrame):
    features, numeric_features, non_log, non_numeric = build_feature_sets(df)
    df_numeric = log_transform(df, numeric_features, non_log)
    df_transformed = pd.concat([df_numeric, df[non_numeric]], axis=1)[features]
    mi_arr = mutual_info_classif(X=df_transformed, y=df['label'])
    df_mi = pd.DataFrame(np.array([df_transformed.columns, mi_arr]).T, columns=['feature', 'mi'])
    df_mi['mi'] = df_mi['mi'].astype(float)
    selected = df_mi[df_mi['mi'] > 0.2]['feature'].tolist()
    preprocessed = pd.concat([df_transformed[selected], df['label']], axis=1)
    return preprocessed, selected

def train_and_eval(df: pd.DataFrame, predictors):
    train, test = train_test_split(df, test_size=0.2, random_state=42)
    X_train, y_train = train[predictors], train['label']
    X_test, y_test = test[predictors], test['label']
    model = DecisionTreeClassifier(criterion='entropy').fit(X_train, y_train)
    y_pred = model.predict(X_test)
    metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'recall': float(recall_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred)),
        'f1': float(f1_score(y_test, y_pred)),
    }
    return model, metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', default=str(Path('UNSW_Train_Test Datasets')/ 'UNSW_NB15_training-set.csv'))
    parser.add_argument('--out-pre', default=str(Path('modifiedDatasets')/ 'preprocessed.csv'))
    parser.add_argument('--out-model-dir', default=str(Path('..')/ '..'/ 'model'/ 'unsw_tabular'))
    args = parser.parse_args()

    csv_path = Path(args.csv)
    out_pre = Path(args.out_pre)
    out_model_dir = Path(args.out_model_dir)

    ensure_dir(out_pre.parent)
    ensure_dir(out_model_dir)

    df = load_unsw(csv_path)
    preprocessed, predictors = preprocess(df)
    preprocessed.to_csv(out_pre, index=False)

    model, metrics = train_and_eval(preprocessed, predictors)

    joblib.dump(model, out_model_dir / 'model_dt.pkl')
    (out_model_dir / 'features.json').write_text(json.dumps({'predictors': predictors}, indent=2))
    (out_model_dir / 'metrics.json').write_text(json.dumps(metrics, indent=2))

    print('Saved:')
    print(f'  preprocessed -> {out_pre}')
    print(f'  model -> {out_model_dir / "model_dt.pkl"}')
    print(f'  features -> {out_model_dir / "features.json"}')
    print(f'  metrics -> {out_model_dir / "metrics.json"}')

if __name__ == '__main__':
    main()
