"""Export a precomputed demo feed for the browser demo page.

Runs the trained two-stage pipeline over an unseen slice of Wednesday traffic
and writes a single JSON file the frontend replays. Inference happens here, so
the page needs no backend: it steps through the feed on a timer and compares
the exported reconstruction error against a user-draggable threshold.
"""

from __future__ import annotations

# TensorFlow 2.16.1 imports the stdlib `distutils`, removed in Python 3.12
# (PEP 632). setuptools ships a shim, but it is installed by a .pth file that
# is not executed in every environment (e.g. sandboxed runners). Installing it
# explicitly makes the import work regardless of how the interpreter started.
try:
    import _distutils_hack

    _distutils_hack.add_shim()
except Exception:  # pragma: no cover - shim already active or not needed
    pass

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from train import (  # noqa: E402
    PRE_DROP_COLS,
    WINDOW_SIZE,
    clean_dataframe,
    drop_cols,
    make_windows,
)

# Unseen slice: the LSTM trained on Monday 100k-150k, XGBoost on Wednesday
# 40k-90k. These rows sit outside the XGBoost training range and were never
# used to fit the scaler. Chosen for dynamic range: benign baseline followed
# by sustained DoS slowloris and a burst of DoS Slowhttptest.
DEMO_START = 67_250
DEMO_WINDOWS = 2_000

# The stream opens here rather than at row 0. The slice is honest in ordering
# (benign first, attacks later), but a viewer should not wait ~7 minutes for
# the first anomaly. The frontend may scrub back to 0; nothing is hidden.
DEFAULT_PLAYHEAD = 980

# Columns shown as human-readable log lines. Kept small: the page renders 20
# rows at a time and the JSON should stay under ~1 MB.
DISPLAY_COLS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Max",
    "Init_Win_bytes_forward",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("dataset"))
    parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--out", type=Path, default=Path("web/demo_feed.json"))
    parser.add_argument("--start", type=int, default=DEMO_START)
    parser.add_argument("--windows", type=int, default=DEMO_WINDOWS)
    parser.add_argument("--playhead", type=int, default=DEFAULT_PLAYHEAD)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    import tensorflow as tf
    from xgboost import XGBClassifier

    scaler = joblib.load(args.artifacts_dir / "scaler.joblib")
    le = joblib.load(args.artifacts_dir / "label_encoder.joblib")
    lstm = tf.keras.models.load_model(args.artifacts_dir / "lstm_autoencoder.keras")
    xgb = XGBClassifier()
    xgb.load_model(args.artifacts_dir / "xgb_model.json")
    threshold = json.loads((args.artifacts_dir / "threshold.json").read_text())["threshold"]

    wednesday = clean_dataframe(
        pd.read_csv(args.data_dir / "Wednesday-workingHours.pcap_ISCX.csv"), "wednesday"
    )
    wednesday["Label"] = wednesday["Label"].str.strip()

    n_rows = args.windows + WINDOW_SIZE - 1
    sl = wednesday.iloc[args.start : args.start + n_rows].reset_index(drop=True)
    if len(sl) < n_rows:
        raise ValueError(f"Slice too short: got {len(sl)} rows, need {n_rows}.")

    labels = sl["Label"].to_numpy()
    features = sl.drop(columns=PRE_DROP_COLS + drop_cols).drop(columns="Label")
    X = scaler.transform(features)
    windows = make_windows(X)

    # Reconstruction error per window. Exported raw, NOT as a verdict: the page
    # compares it against a threshold the viewer drags, so the binary decision
    # must be recomputable client-side.
    recon = lstm.predict(windows, batch_size=512, verbose=0)
    errors = np.mean(np.abs(windows - recon), axis=(1, 2))

    window_labels = labels[WINDOW_SIZE - 1 :]

    # XGBoost prediction for EVERY window, not only those flagged at the
    # calibrated threshold. Lowering the threshold in the UI admits new windows
    # to the classifier, and the page must already know what it would say.
    xgb_pred = le.inverse_transform(xgb.predict(windows[:, -1, :]))

    known_classes = [str(c) for c in le.classes_]

    rows = []
    for i in range(len(sl)):
        r = sl.iloc[i]
        rows.append(
            {
                "i": i,
                "label": str(labels[i]),
                "f": [round(float(r[c]), 3) for c in DISPLAY_COLS],
            }
        )

    window_records = []
    for w in range(len(errors)):
        truth = str(window_labels[w])
        window_records.append(
            {
                "w": w,
                "end_row": w + WINDOW_SIZE - 1,
                "err": round(float(errors[w]), 6),
                "truth": truth,
                "xgb": str(xgb_pred[w]),
                # Ground truth the classifier has no label for. None here, but
                # the field exists so the frontend's unknown-attack branch is
                # exercised if a future slice includes GoldenEye/Heartbleed.
                "unknown": truth != "BENIGN" and truth not in known_classes,
            }
        )

    feed = {
        "meta": {
            "source": "CIC-IDS2017 Wednesday-workingHours (MachineLearningCVE)",
            "absolute_rows": [args.start, args.start + n_rows],
            "note": (
                "Unseen slice: outside the Wednesday 40k-90k range used to fit "
                "XGBoost, and the scaler was fitted on Monday benign traffic only."
            ),
            "window_size": WINDOW_SIZE,
            "n_features": int(X.shape[1]),
            "calibrated_threshold": threshold,
            "known_classes": known_classes,
            "display_cols": DISPLAY_COLS,
            "playhead": args.playhead,
        },
        "rows": rows,
        "windows": window_records,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(feed, separators=(",", ":")))

    flagged = errors > threshold
    print(f"rows {args.start}-{args.start + n_rows} -> {len(window_records)} windows")
    print(f"error range {errors.min():.4f} - {errors.max():.4f} (threshold {threshold:.4f})")
    print(f"flagged at calibrated threshold: {flagged.sum()} ({flagged.mean() * 100:.1f}%)")
    print(f"wrote {args.out} ({args.out.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
