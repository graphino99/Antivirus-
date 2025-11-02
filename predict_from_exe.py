import argparse
import json
import os
from typing import List

import pandas as pd
from xgboost import XGBClassifier

from extract_features import extract_features_from_exe
from model_utils import load_schema, load_model, prepare_features


def main() -> None:

    parser = argparse.ArgumentParser(description="Predict malware probability for a PE .exe using trained XGBoost model")
    parser.add_argument("--model_dir", required=True, help="Directory with xgb_model.json and feature_schema.json")
    parser.add_argument("--exe", required=True, help="Path to the .exe (PE) file to analyze")
    parser.add_argument("--threshold", type=float, default=0.5, help="Classification threshold (default 0.5)")
    args = parser.parse_args()

    if not os.path.exists(args.exe):
        raise FileNotFoundError(f"EXE not found: {args.exe}")

    schema = load_schema(os.path.join(args.model_dir, "feature_schema.json"))
    feature_cols: List[str] = schema["feature_columns"]

    feat = extract_features_from_exe(args.exe)
    df = pd.DataFrame([feat])
    X = prepare_features(df, feature_cols)

    model: XGBClassifier = load_model(args.model_dir)
    proba = float(model.predict_proba(X.values)[:, 1][0])
    pred = int(proba >= args.threshold)

    result = {
        "file": os.path.basename(args.exe),
        "malicious_probability": proba,
        "prediction": pred,
        "label": "malicious" if pred == 1 else "benign",
        "threshold": args.threshold,
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()


