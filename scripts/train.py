"""Train the two-stage log anomaly detector from the CIC-IDS2017 CSV files."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.layers import Dense, Input, LSTM, RepeatVector, TimeDistributed
from tensorflow.keras.models import Model
from xgboost import XGBClassifier


WINDOW_SIZE = 20
SPLIT = 0.80
CORRELATION_THRESHOLD = 0.90

# Lista final de features a eliminar tras inspección manual de los 42 pares
# con threshold (p) >= 0.9 y del heatmap filtrado. Para cada cluster se conserva
# la variable más interpretable frente a sus pares correlacionados.
#
# Comparación realizada con IA:
# Se usó la Inteligencia Artificial (Claude) para detectar las variables mas
# representativas en un contexto de Ciberseguridad.
drop_cols = [
    # Duración del flujo. 'Flow Duration' es la métrica más directa; los
    # totales de IAT son reformulaciones equivalentes.
    "Fwd IAT Total",  # rho=0.997 con Flow Duration
    "Bwd IAT Total",  # rho=0.954 con Flow Duration

    # Estadísticas de tamaño de paquete. 'Average Packet Size' es el nombre
    # más interpretable y absorbe a medias, std, varianza, max, y equivalentes Bwd.
    "Packet Length Mean",  # rho=0.996 con Average Packet Size
    "Packet Length Std",  # rho=0.913 con Average Packet Size
    "Packet Length Variance",  # rho=0.919 con Average Packet Size
    "Max Packet Length",  # rho=0.969 con Packet Length Std
    "Bwd Packet Length Max",  # rho=0.960 con Max Packet Length
    "Bwd Packet Length Mean",  # rho=0.931 con Average Packet Size
    "Bwd Packet Length Std",  # rho=0.927 con Packet Length Std

    # Tasa de paquetes. 'Fwd Packets/s' ya refleja la tasa global.
    "Flow Packets/s",  # rho=0.994 con Fwd Packets/s

    # Máximo IAT. 'Flow IAT Max' es más general que su versión Fwd.
    "Fwd IAT Max",  # rho=0.993 con Flow IAT Max

    # Métricas de inactividad e IAT backward. 'Idle Max' captura la pausa más
    # larga del flujo, señal clave para ataques lentos (slowloris, Slowhttptest).
    "Idle Mean",  # rho=0.993 con Idle Max
    "Idle Min",  # rho=0.971 con Idle Max
    "Bwd IAT Max",  # rho=0.932 con Idle Max
    "Bwd IAT Mean",  # rho=0.972 con Bwd IAT Min / rho=0.920 con Flow IAT Std
    "Bwd IAT Min",  # rho=0.972 con Bwd IAT Mean
    "Flow IAT Std",  # rho=0.920 con Bwd IAT Mean / rho=0.905 con Idle Mean

    # IAT forward medio. 'Fwd IAT Mean' resume min y media.
    "Fwd IAT Min",  # rho=0.978 con Fwd IAT Mean

    # Conteo de paquetes y longitud de cabeceras. 'Total Fwd packets' es la
    # métrica más interpretable para RCA; las demás miden lo mismo desde otra dirección.
    "Total Backward Packets",  # rho=0.958 con Total Fwd Packets
    "Total Length of Bwd Packets",  # rho=0.931 con Total Fwd Packets
    "Fwd Header Length",  # rho=0.960 con Total Fwd Packets
    "Bwd Header Length",  # rho=0.917 con Total Fwd Packets

    # Tamaño de paquete forward. Conservamos el máximo.
    "Fwd Packet Length Std",  # rho=0.958 con Fwd Packet Length Max

    # Tiempo activo. 'Active Mean' resume a 'Active Min'.
    "Active Min",  # rho=0.909 con Active Mean
]

DUPLICATED_COLS = [
    "Fwd Header Length.1",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
]
BULK_COLS = [
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
]
CONSTANT_COLS = ["Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "CWE Flag Count"]
PRE_DROP_COLS = DUPLICATED_COLS + BULK_COLS + CONSTANT_COLS + ["Destination Port"]


def make_windows(X: np.ndarray, window: int = WINDOW_SIZE) -> np.ndarray:
    """Convert (N, F) into consecutive sliding windows of shape (N-window+1, window, F)."""
    if X.ndim != 2 or X.shape[0] < window:
        raise ValueError(f"Expected at least {window} rows in a 2-D array, got {X.shape}.")
    return np.stack([X[i : i + window] for i in range(X.shape[0] - window + 1)])


def clean_dataframe(df: pd.DataFrame, name: str) -> pd.DataFrame:
    """Remove CICFlowMeter infinities/NaNs while preserving row order."""
    before = len(df)
    df = df.copy()
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"{name}: {before} -> {len(df)} filas (descartadas {before - len(df)})")
    return df


def build_model(features: int) -> Model:
    inputs = Input(shape=(WINDOW_SIZE, features))
    encoded = LSTM(64, activation="tanh", return_sequences=False)(inputs)
    bottleneck = Dense(32, activation="relu")(encoded)
    repeated = RepeatVector(WINDOW_SIZE)(bottleneck)
    decoded = LSTM(64, activation="tanh", return_sequences=True)(repeated)
    outputs = TimeDistributed(Dense(features))(decoded)
    model = Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer="adam", loss="mae")
    return model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("dataset"))
    parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    random.seed(args.seed)
    np.random.seed(args.seed)
    try:
        import tensorflow as tf

        tf.random.set_seed(args.seed)
    except ImportError:
        raise

    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    monday = clean_dataframe(
        pd.read_csv(args.data_dir / "Monday-WorkingHours.pcap_ISCX.csv"), "monday_ds"
    )
    wednesday = clean_dataframe(
        pd.read_csv(args.data_dir / "Wednesday-workingHours.pcap_ISCX.csv"), "wednesday_ds"
    )
    monday = monday.iloc[100_000:150_000].reset_index(drop=True)
    wednesday = wednesday.iloc[40_000:90_000].reset_index(drop=True)
    wednesday["Label"] = wednesday["Label"].str.strip()

    monday = monday.drop(columns=PRE_DROP_COLS + drop_cols)
    wednesday = wednesday.drop(columns=PRE_DROP_COLS + drop_cols)
    if list(monday.columns) != list(wednesday.columns):
        raise ValueError("Monday and Wednesday feature columns do not match after selection.")

    X_monday = monday.drop(columns="Label")
    X_wednesday = wednesday.drop(columns="Label")
    y_wednesday = wednesday["Label"]

    scaler = StandardScaler()
    X_monday_s = scaler.fit_transform(X_monday)
    X_wednesday_s = scaler.transform(X_wednesday)
    joblib.dump(scaler, args.artifacts_dir / "scaler.joblib")

    # La LSTM RNN requiere (muestras, pasos_temporales y features). La entrada
    # (50000, 36) se convierte en (49981, 20, 36) con stride=1.
    X_monday_windows = make_windows(X_monday_s)
    X_wednesday_windows = make_windows(X_wednesday_s)
    assert np.allclose(X_monday_windows[0], X_monday_s[0:20])
    assert np.allclose(X_monday_windows[1], X_monday_s[1:21])

    train_m = int(X_monday_windows.shape[0] * SPLIT)
    X_train_lstm = X_monday_windows[:train_m]
    X_val_lstm = X_monday_windows[train_m:]

    le = LabelEncoder()
    X_train, X_test, y_train, y_test = train_test_split(
        X_wednesday_s, y_wednesday, test_size=0.3, stratify=y_wednesday, random_state=args.seed
    )
    y_train_enc = le.fit_transform(y_train)
    y_test_enc = le.transform(y_test)
    joblib.dump(le, args.artifacts_dir / "label_encoder.joblib")

    # Pesos inversamente proporcionales a la frecuencia de cada clase para
    # corregir el desbalance entre BENIGN y los ataques minoritarios.
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train_enc)
    xgb_model = XGBClassifier(
        n_estimators=30, max_depth=6, learning_rate=0.1, tree_method="hist",
        objective="multi:softprob", eval_metric="mlogloss", n_jobs=-1,
        random_state=args.seed, verbosity=0,
    )
    xgb_model.fit(
        X_train, y_train_enc, sample_weight=sample_weights,
        eval_set=[(X_train, y_train_enc), (X_test, y_test_enc)],
        verbose=False,
    )
    xgb_model.save_model(args.artifacts_dir / "xgb_model.json")

    xgb_report = classification_report(
        le.inverse_transform(y_test_enc), le.inverse_transform(xgb_model.predict(X_test)),
        output_dict=True,
    )

    # Tamaño de ventana (20): captura patrones de ráfagas típicos de ataques
    # DoS sin elevar innecesariamente el coste computacional.
    lstm_model = build_model(X_monday_windows.shape[2])
    early_stop = EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True, verbose=1)
    history = lstm_model.fit(
        X_train_lstm, X_train_lstm, epochs=args.epochs, batch_size=args.batch_size,
        validation_data=(X_val_lstm, X_val_lstm), callbacks=[early_stop],
        shuffle=False, verbose=1,
    )
    lstm_model.save(args.artifacts_dir / "lstm_autoencoder.keras")

    X_val_pred = lstm_model.predict(X_val_lstm, batch_size=args.batch_size, verbose=0)
    val_errors = np.mean(np.abs(X_val_lstm - X_val_pred), axis=(1, 2))
    threshold = float(np.percentile(val_errors, 95))
    X_wednesday_pred = lstm_model.predict(
        X_wednesday_windows, batch_size=args.batch_size, verbose=0
    )
    reconstruction_errors = np.mean(
        np.abs(X_wednesday_windows - X_wednesday_pred), axis=(1, 2)
    )
    y_windows = y_wednesday.to_numpy()[WINDOW_SIZE - 1 :]
    y_pred_binary = (reconstruction_errors > threshold).astype(int)

    # Integración LSTM -> XGBoost (notebook celdas 84-93).
    # El LSTM marca ventanas anómalas; XGBoost clasifica el tipo de ataque
    # usando el último flujo de cada ventana como representación.
    anomaly_idx = np.where(y_pred_binary == 1)[0]
    y_final_pred = np.array(["BENIGN"] * len(y_windows), dtype=object)
    if len(anomaly_idx) > 0:
        X_anomalies = X_wednesday_windows[anomaly_idx, -1, :]
        y_final_pred[anomaly_idx] = le.inverse_transform(
            xgb_model.predict(X_anomalies)
        )

    metrics = {
        "features": list(X_monday.columns),
        "window_size": WINDOW_SIZE,
        "threshold_percentile": 95,
        "threshold": threshold,
        "xgboost": xgb_report,
        "lstm_binary": classification_report(
            (y_windows != "BENIGN").astype(int), y_pred_binary,
            target_names=["BENIGN", "ATAQUE"], output_dict=True,
        ),
        "pipeline": classification_report(
            y_windows, y_final_pred, output_dict=True, zero_division=0
        ),
        "training": {
            "epochs_completed": len(history.history["loss"]),
            "best_epoch": int(np.argmin(history.history["val_loss"])) + 1,
            "best_val_loss": float(np.min(history.history["val_loss"])),
        },
    }
    (args.artifacts_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (args.artifacts_dir / "threshold.json").write_text(
        json.dumps({"threshold": threshold, "percentile": 95}, indent=2)
    )
    (args.artifacts_dir / "training_history.json").write_text(
        json.dumps(history.history, indent=2)
    )
    print(f"Features finales: {len(X_monday.columns)}")
    print(f"Umbral (percentil 95): {threshold:.4f}")
    print(f"Artifacts guardados en {args.artifacts_dir}")


if __name__ == "__main__":
    main()
