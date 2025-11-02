import argparse
import json
import os
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier


def infer_label_series(series: pd.Series) -> pd.Series:

    if series.dtype == bool:
        return series.astype(int)

    if pd.api.types.is_numeric_dtype(series):
        # Assume already encoded 0/1
        return series.astype(int)

    # Try common string mappings
    lowercase = series.astype(str).str.strip().str.lower()
    mapping = {
        "malware": 1,
        "malicious": 1,
        "bad": 1,
        "1": 1,
        "benign": 0,
        "good": 0,
        "clean": 0,
        "0": 0,
    }
    mapped = lowercase.map(mapping)
    if mapped.isna().any():
        # Fallback: treat any non-benign-like value as 1, benign-like as 0
        mapped = lowercase.isin(["benign", "good", "clean", "0"]).astype(int)
    return mapped


def coerce_numeric(df: pd.DataFrame) -> pd.DataFrame:

    coerced = df.copy()

    for col in coerced.columns:
        if pd.api.types.is_bool_dtype(coerced[col]):
            coerced[col] = coerced[col].astype(int)
            continue

        if pd.api.types.is_numeric_dtype(coerced[col]):
            continue

        # Attempt to coerce strings like "True"/"False"/"yes"/"no"
        as_str = coerced[col].astype(str).str.strip().str.lower()
        if as_str.isin(["true", "false", "yes", "no"]).all():
            coerced[col] = as_str.isin(["true", "yes"]).astype(int)
            continue

        # Try numeric coercion; non-numeric will become NaN and later dropped if entire column non-numeric
        coerced[col] = pd.to_numeric(coerced[col], errors="coerce")

    return coerced


def select_feature_columns(df: pd.DataFrame, label_col: str) -> List[str]:

    excluded_non_numeric = set()
    # Common non-numeric identifier or free-text columns to exclude
    for candidate in ["sha256", "ascii_list", "imports_list"]:
        if candidate in df.columns:
            excluded_non_numeric.add(candidate)

    numeric_or_bool_cols = []
    for col in df.columns:
        if col == label_col:
            continue
        if col in excluded_non_numeric:
            continue
        if pd.api.types.is_numeric_dtype(df[col]) or pd.api.types.is_bool_dtype(df[col]):
            numeric_or_bool_cols.append(col)

    return numeric_or_bool_cols


def compute_scale_pos_weight(y: np.ndarray) -> float:

    positives = float((y == 1).sum())
    negatives = float((y == 0).sum())
    if positives == 0:
        return 1.0
    return max(1.0, negatives / max(1.0, positives))


def train_model(
    csv_path: str,
    output_dir: str,
    label_col: str = "label",
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[XGBClassifier, List[str]]:

    df = pd.read_csv(csv_path)

    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found in CSV.")

    y = infer_label_series(df[label_col]).values

    # Prepare features
    X_raw = df.drop(columns=[label_col])
    X_coerced = coerce_numeric(X_raw)

    # Keep only numeric/bool columns
    feature_cols = select_feature_columns(X_coerced, label_col="__unused__")
    if not feature_cols:
        raise ValueError("No numeric/boolean feature columns found after coercion.")
    X = X_coerced[feature_cols].fillna(0)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y if len(np.unique(y)) == 2 else None
    )

    spw = compute_scale_pos_weight(y_train)

    model = XGBClassifier(
        n_estimators=600,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        reg_alpha=0.0,
        n_jobs=-1,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=spw,
        tree_method="hist",
        random_state=random_state,
    )

    model.fit(X_train, y_train)

    y_val_proba = model.predict_proba(X_val)[:, 1]
    y_val_pred = (y_val_proba >= 0.5).astype(int)

    try:
        auc = roc_auc_score(y_val, y_val_proba)
    except Exception:
        auc = float("nan")

    print("Validation ROC-AUC:", auc)
    print("Validation classification report:\n", classification_report(y_val, y_val_pred, digits=4))

    os.makedirs(output_dir, exist_ok=True)

    # Save model
    model_path = os.path.join(output_dir, "xgb_model.json")
    model.save_model(model_path)

    # Save feature schema
    schema = {
        "feature_columns": feature_cols,
        "label_column": label_col,
    }
    schema_path = os.path.join(output_dir, "feature_schema.json")
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    # Also save a lightweight sklearn-compatible wrapper via joblib for flexibility
    joblib.dump({"model": model, "feature_columns": feature_cols}, os.path.join(output_dir, "model_joblib.pkl"))

    print(f"Saved model to: {model_path}")
    print(f"Saved schema to: {schema_path}")
    return model, feature_cols


def main() -> None:

    parser = argparse.ArgumentParser(description="Train XGBoost malware classifier on CSV")
    parser.add_argument(
        "--csv",
        required=True,
        help="Path to training CSV (must include 'label' column)",
    )
    parser.add_argument(
        "--out",
        default="model_artifacts",
        help="Output directory to save model and schema",
    )
    parser.add_argument(
        "--test_size",
        type=float,
        default=0.2,
        help="Validation split fraction",
    )
    parser.add_argument(
        "--label",
        default="label",
        help="Label column name (default: label)",
    )

    args = parser.parse_args()

    train_model(csv_path=args.csv, output_dir=args.out, label_col=args.label, test_size=args.test_size)


if __name__ == "__main__":
    main()


