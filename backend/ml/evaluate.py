"""
Model Evaluation and Metrics Computation for Network Intrusion Detection System.
Calculates multiclass metrics, confusion matrix, ROC-AUC, FPR, FNR, and class reports.
"""

from typing import Dict, List, Any
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    roc_auc_score,
    classification_report
)

def evaluate_classifier(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    class_names: List[str]
) -> Dict[str, Any]:
    """
    Computes rigorous evaluation metrics for multi-class network intrusion detection.
    Never fabricates metrics. Handles class edge cases safely.
    """
    acc = float(accuracy_score(y_true, y_pred))
    
    # Macro metrics
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    # Weighted metrics
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )
    
    # Per-class metrics
    p_class, r_class, f1_class, support_class = precision_recall_fscore_support(
        y_true, y_pred, average=None, labels=range(len(class_names)), zero_division=0
    )
    
    per_class_metrics: List[Dict[str, Any]] = []
    for i, name in enumerate(class_names):
        per_class_metrics.append({
            "class_name": name,
            "precision": round(float(p_class[i]), 4),
            "recall": round(float(r_class[i]), 4),
            "f1_score": round(float(f1_class[i]), 4),
            "support": int(support_class[i])
        })

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=range(len(class_names)))
    
    # Calculate False Positive Rate (Benign classified as Attack) and False Negative Rate (Attack classified as Benign)
    # Assuming 'BENIGN' is in class_names
    fpr = 0.0
    fnr = 0.0
    benign_idx = -1
    for idx, c in enumerate(class_names):
        if c.upper() == "BENIGN":
            benign_idx = idx
            break
            
    if benign_idx != -1:
        total_benign = int(cm[benign_idx].sum())
        benign_as_attack = int(total_benign - cm[benign_idx, benign_idx])
        fpr = float(benign_as_attack / max(total_benign, 1))

        # False negative: true attack predicted as benign
        total_attacks = int(cm.sum() - total_benign)
        attacks_as_benign = int(cm[:, benign_idx].sum() - cm[benign_idx, benign_idx])
        fnr = float(attacks_as_benign / max(total_attacks, 1))

    # Multiclass ROC-AUC (ovr)
    roc_auc = None
    try:
        if y_proba is not None and y_proba.shape[1] == len(class_names) and len(np.unique(y_true)) > 1:
            roc_auc = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="weighted"))
    except Exception:
        roc_auc = None

    return {
        "accuracy": round(acc, 4),
        "precision_macro": round(float(p_macro), 4),
        "recall_macro": round(float(r_macro), 4),
        "f1_macro": round(float(f1_macro), 4),
        "precision_weighted": round(float(p_weighted), 4),
        "recall_weighted": round(float(r_weighted), 4),
        "f1_weighted": round(float(f1_weighted), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "confusion_matrix": cm.tolist(),
        "classes": class_names,
        "per_class": per_class_metrics
    }

