import json
import os
from io import StringIO
from typing import Dict, List

import joblib
import pandas as pd
from xgboost import XGBClassifier


def load_schema(schema_path: str) -> Dict:
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_model(model_dir: str) -> XGBClassifier:
    """Load XGBoost model, preferring joblib format for sklearn compatibility."""
    # Try loading from joblib first (preserves sklearn attributes)
    model_joblib = os.path.join(model_dir, "model_joblib.pkl")
    if os.path.exists(model_joblib):
        try:
            loaded = joblib.load(model_joblib)
            if isinstance(loaded, dict) and "model" in loaded:
                model = loaded["model"]
            else:
                model = loaded
            # Ensure model is properly initialized
            if not hasattr(model, "n_classes_"):
                model.n_classes_ = len(model.classes_) if hasattr(model, "classes_") else 2
            return model
        except Exception as e:
            # Fall back to JSON if joblib fails
            pass
    
    # Fallback to JSON loading
    model_json = os.path.join(model_dir, "xgb_model.json")
    if not os.path.exists(model_json):
        raise FileNotFoundError(f"Model file not found: {model_json}")
    
    # Create model with explicit binary classification parameters
    model = XGBClassifier(objective="binary:logistic")
    model.load_model(model_json)
    
    # Initialize sklearn attributes that may be missing after JSON load
    # For binary classification, we need n_classes_ and classes_
    if not hasattr(model, "classes_") or model.classes_ is None:
        model.classes_ = [0, 1]
    if not hasattr(model, "n_classes_") or model.n_classes_ is None:
        model.n_classes_ = len(model.classes_) if hasattr(model, "classes_") else 2
    
    # Try to get classes from the booster if available
    try:
        if hasattr(model, "get_booster"):
            # This helps ensure the model is fully initialized
            _ = model.get_booster()
    except Exception:
        pass
    
    return model


def prepare_features(df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
    coerced = df.copy()
    for col in coerced.columns:
        if coerced[col].dtype == bool:
            coerced[col] = coerced[col].astype(int)
        else:
            as_str = coerced[col].astype(str).str.strip().str.lower()
            if as_str.isin(["true", "false", "yes", "no"]).all():
                coerced[col] = as_str.isin(["true", "yes"]).astype(int)
            else:
                coerced[col] = pd.to_numeric(coerced[col], errors="coerce")

    for col in feature_cols:
        if col not in coerced.columns:
            coerced[col] = 0
    extra = [c for c in coerced.columns if c not in feature_cols]
    if extra:
        coerced = coerced.drop(columns=extra)

    coerced = coerced[feature_cols].fillna(0)
    return coerced


