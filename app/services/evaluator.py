"""Detection-quality evaluation.

Fixes the MVP's headline bug: it reported precision and recall as
`correct/total`, which is accuracy twice under two different names. Here
precision and recall are computed per class from the confusion counts, plus
binary malicious/benign FPR and FNR, which is what a SOC actually tunes on.
"""

from __future__ import annotations

from app.models.email_models import EmailRecord
from app.services.email_parser import load_expected_labels

BENIGN_LABEL = "Benign"


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def per_class_metrics(pairs: list[tuple[str, str]]) -> list[dict]:
    """pairs = [(expected, predicted), ...]"""
    labels = sorted({label for pair in pairs for label in pair})
    rows = []
    for label in labels:
        tp = sum(1 for exp, pred in pairs if exp == label and pred == label)
        fp = sum(1 for exp, pred in pairs if exp != label and pred == label)
        fn = sum(1 for exp, pred in pairs if exp == label and pred != label)
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        rows.append(
            {
                "Class": label,
                "Support": tp + fn,
                "TP": tp,
                "FP": fp,
                "FN": fn,
                "Precision": round(precision, 3),
                "Recall": round(recall, 3),
                "F1": round(_safe_div(2 * precision * recall, precision + recall), 3),
            }
        )
    return rows


def binary_metrics(pairs: list[tuple[str, str]]) -> dict[str, float]:
    """Collapse to malicious vs benign - the decision the mail gateway makes."""
    tp = sum(1 for exp, pred in pairs if exp != BENIGN_LABEL and pred != BENIGN_LABEL)
    tn = sum(1 for exp, pred in pairs if exp == BENIGN_LABEL and pred == BENIGN_LABEL)
    fp = sum(1 for exp, pred in pairs if exp == BENIGN_LABEL and pred != BENIGN_LABEL)
    fn = sum(1 for exp, pred in pairs if exp != BENIGN_LABEL and pred == BENIGN_LABEL)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "Accuracy": round(_safe_div(tp + tn, len(pairs)), 3),
        "Precision": round(precision, 3),
        "Recall": round(recall, 3),
        "F1": round(_safe_div(2 * precision * recall, precision + recall), 3),
        "FPR": round(_safe_div(fp, fp + tn), 3),
        "FNR": round(_safe_div(fn, fn + tp), 3),
    }


def confusion_pairs(emails: list[EmailRecord], predictions: dict[str, str]) -> list[tuple[str, str]]:
    """Build (expected, predicted) pairs, skipping any message with no label.

    The MVP used a dict literal and raised KeyError on any new message; an
    unlabelled message is now simply excluded from the metrics.
    """
    labels = load_expected_labels()
    pairs = []
    for email in emails:
        label = labels.get(email.id)
        predicted = predictions.get(email.id)
        if label and predicted:
            pairs.append((label["expected_verdict"], predicted))
    return pairs


def detail_rows(emails: list[EmailRecord], predictions: dict[str, str], confidences: dict[str, float]) -> list[dict]:
    labels = load_expected_labels()
    rows = []
    for email in emails:
        label = labels.get(email.id)
        predicted = predictions.get(email.id, "(not scored)")
        expected = label["expected_verdict"] if label else "(unlabelled)"
        rows.append(
            {
                "Message ID": email.id,
                "Scenario": email.scenario,
                "Expected": expected,
                "Predicted": predicted,
                "Confidence": round(confidences.get(email.id, 0.0), 2),
                "Agreement": expected == predicted if label else None,
            }
        )
    return rows


def low_confidence_queue(
    emails: list[EmailRecord], confidences: dict[str, float], threshold: float = 0.8
) -> list[dict]:
    """Messages the system is least sure about - where an analyst adds the most value."""
    rows = [
        {"Message ID": e.id, "Scenario": e.scenario, "Confidence": round(confidences.get(e.id, 0.0), 2)}
        for e in emails
        if confidences.get(e.id, 1.0) < threshold
    ]
    return sorted(rows, key=lambda row: row["Confidence"])


def unlabelled(emails: list[EmailRecord]) -> list[str]:
    labels = load_expected_labels()
    return [e.id for e in emails if e.id not in labels]
