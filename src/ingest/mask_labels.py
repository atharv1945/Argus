"""
ARGUS Ingestion Utility — Label-Hiding Discipline
================================──────────────────
Provides utility functions to mask or strip ground truth labels ('is_malicious',
'attack_type', 'attack_instance_id') from telemetry DataFrames before inference.

CRITICAL DISCIPLINE RULE:
    All feature extraction, rolling baselines, graph construction, and model
    inference code MUST process un-labeled / masked telemetry data. Ground truth
    labels ('is_malicious', 'attack_type') must ONLY be accessed during final metric
    evaluation (precision/recall/F1 scoring).

Usage:
    from src.ingest.mask_labels import mask_labels, strip_labels

    unlabeled_df = mask_labels(raw_df)
"""

import pandas as pd

def mask_labels(df: pd.DataFrame, inplace: bool = False) -> pd.DataFrame:
    """
    Masks ground truth label columns in the DataFrame with benign default values.
    Returns a clean DataFrame suitable for feature engineering and model inference.
    """
    if not inplace:
        df = df.copy()

    if "is_malicious" in df.columns:
        df["is_malicious"] = False
    if "attack_type" in df.columns:
        df["attack_type"] = "none"
    if "attack_instance_id" in df.columns:
        df["attack_instance_id"] = "none"

    return df

def strip_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Completely removes ground truth label columns from the DataFrame.
    """
    cols_to_drop = [c for c in ["is_malicious", "attack_type", "attack_instance_id"] if c in df.columns]
    return df.drop(columns=cols_to_drop)

if __name__ == "__main__":
    print("[OK] src/ingest/mask_labels.py module initialized.")
