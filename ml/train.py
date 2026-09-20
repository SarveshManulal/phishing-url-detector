"""Optional: train a Random Forest on the same URL features the rule engine uses.

Usage:
    python -m ml.train --data data/sample_urls.csv --out model.joblib

The CSV needs two columns: ``url`` and ``label`` (1 = phishing, 0 = legitimate).
data/sample_urls.csv is only a smoke-test set. For real results, use a large
public dataset (PhishTank / OpenPhish for phishing URLs, Tranco top sites for
legitimate ones) and report precision, recall and F1.
"""

from __future__ import annotations

import argparse
import csv

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from phishing_detector.features import FEATURE_NAMES, extract_features, feature_vector


def load(path: str):
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            X.append(feature_vector(extract_features(row["url"])))
            y.append(int(row["label"]))
    return X, y


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="data/sample_urls.csv")
    p.add_argument("--out", default="model.joblib")
    p.add_argument("--test-size", type=float, default=0.3)
    args = p.parse_args()

    X, y = load(args.data)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=42
    )
    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)

    print(classification_report(y_test, model.predict(X_test), target_names=["legitimate", "phishing"], zero_division=0))
    ranked = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1])[:8]
    print("Top features:")
    for name, weight in ranked:
        print(f"  {name:22s} {weight:.3f}")

    joblib.dump(model, args.out)
    print(f"\nSaved model to {args.out}")


if __name__ == "__main__":
    main()
