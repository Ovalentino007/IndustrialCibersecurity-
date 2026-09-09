#!/usr/bin/env python3
"""
Entrenamiento del clasificador multiclase de ataques a partir del dataset
generado por build_dataset.py.
 
USO:
    pip3 install scikit-learn pandas --break-system-packages   # si hace falta
    python3 train_model.py --dataset dataset.csv
 
------------------------------------------------------------------------
DECISIONES METODOLOGICAS (para documentar en la memoria)
------------------------------------------------------------------------
 
1. MODELO BASE: Random Forest. Justificacion para un dataset de este tipo
   (tabular, mezcla de variables numericas y categoricas, tamano pequeno-
   mediano, necesidad de interpretabilidad para un contexto de seguridad
   OT donde hay que poder explicar por que se clasifico algo como
   ataque): es el punto de partida estandar en la literatura de ML para
   NIDS/IDS (usado como baseline en CICIDS2017, NSL-KDD y trabajos
   similares), maneja bien variables no normalizadas y proporciona
   `feature_importances_` directamente.
 
2. SPLIT TRAIN/TEST: por TIEMPO, no aleatorio. Random split rompe la
   independencia entre muestras -- muchas conexiones de un mismo ataque
   son casi identicas entre si; un split aleatorio dejaria copias casi
   identicas de la MISMA rafaga de ataque en train y en test,
   sobreestimando artificialmente el rendimiento.
 
3. DESBALANCEO DE CLASES: se espera (y es realista, coincide con
   cualquier red real) que "benign" domine el dataset. Se usa
   `class_weight="balanced"` en vez de sobre/infra-muestreo articial
   para no fabricar conexiones sinteticas irreales sobre un
   protocolo tan estructurado como Modbus.
 
4. METRICAS: para multiclase con desbalanceo, accuracy global es enganosa
   (un modelo que dijera siempre "benign" tendria accuracy alta). Se
   reportan precision/recall/F1 POR CLASE y su macro-promedio (todas las
   clases pesan igual, no solo la mayoritaria), mas la matriz de
   confusion completa -- que es ademas el resultado mas facil de leer e
   interpretar en la memoria.
 
5. Variables categoricas (`proto`, `service`, `conn_state`) se codifican
   con one-hot encoding; `src`/`dst`/`src_port`/`dst_port` se EXCLUYEN
   deliberadamente del entrenamiento (usarlas dejaria que el modelo
   memorizase "esta IP siempre es el atacante" en vez de aprender el
   PATRON de trafico, que es lo que de verdad generaliza a un atacante
   con otra IP).
 
6. FEATURES DE "PAYLOAD" (sugerencia del tutor del TFG): ademas de las
   estadisticas de flujo de conn.log, se incorporan atributos derivados
   del propio contenido de la alerta -- en concreto, para trafico Modbus,
   el detalle de la escritura (registro/direccion, valor, tipo) capturado
   por el log propio modbus_writes.log (local.zeek v9). `modbus_write_type`
   se trata como categorica (incluye el valor "none" para conexiones sin
   ninguna escritura Modbus asociada -- la inmensa mayoria); el resto se
   tratan como numericas, con -1/0 como valores neutros para conexiones
   sin escritura. Se espera que estas columnas sean especialmente
   discriminantes para la clase `modbus_unauthorized_write`, ya que
   capturan la señal mas directa posible (QUE se escribio), en vez de solo
   estadisticas indirectas de flujo.
"""
 
import argparse
 
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
 
CATEGORICAL_FEATURES = ["proto", "service", "conn_state", "modbus_last_write_type"]
NUMERIC_FEATURES = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "bytes_per_pkt_orig", "bytes_per_pkt_resp",
    "conns_same_src_10s", "distinct_dst_ports_src_60s", "distinct_dst_hosts_src_60s",
    "hist_len", "hist_syn", "hist_fin", "hist_rst", "hist_ack",
    "modbus_write_count", "modbus_last_write_address", "modbus_last_write_count",
]
 
def temporal_split_per_class(df, train_fraction):
    
    train_parts, test_parts = [], []
    for label, group in df.groupby("label"):
        group = group.sort_values("ts")
        n = len(group)
        split_idx = int(n * train_fraction)
        if n >= 2:
            split_idx = max(1, min(split_idx, n - 1))
        train_parts.append(group.iloc[:split_idx])
        test_parts.append(group.iloc[split_idx:])
    train_df = pd.concat(train_parts).sort_values("ts").reset_index(drop=True)
    test_df = pd.concat(test_parts).sort_values("ts").reset_index(drop=True)
    return train_df, test_df

def main():

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--train-fraction", type=float, default=0.7)
    args = parser.parse_args()
 
    df = pd.read_csv(args.dataset).sort_values("ts").reset_index(drop=True)
    print(f"[+] Dataset cargado: {len(df)} filas")
    print(df["label"].value_counts())
    
    train_df, test_df = temporal_split_per_class(df, args.train_fraction)
    print(f"[+] Split temporal POR CLASE: {len(train_df)} train / {len(test_df)} test")
    print("    (reparto train/test por clase, cronologico dentro de cada una)")
    counts_train = train_df["label"].value_counts()
    counts_test = test_df["label"].value_counts()
    for label in sorted(df["label"].unique()):
        print(f"      {label:30s} train={counts_train.get(label, 0):>8d}   "
              f"test={counts_test.get(label, 0):>8d}")
 
 
    X_train = train_df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
    y_train = train_df["label"]
    X_test = test_df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
    y_test = test_df["label"]
 
    preprocessor = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
    ], remainder="passthrough")
 
    clf = Pipeline([
        ("prep", preprocessor),
        ("model", RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1
        )),
    ])
 
    print("[+] Entrenando Random Forest...")
    clf.fit(X_train, y_train)
 
    y_pred = clf.predict(X_test)
 
    print("\n[+] Informe de clasificacion (test, split temporal):")
    print(classification_report(y_test, y_pred, zero_division=0))
 
    print("[+] Matriz de confusion (filas=real, columnas=predicho):")
    labels = sorted(y_test.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    header = "".join(f"{l[:12]:>14s}" for l in labels)
    print(f"{'':14s}{header}")
    for label, row in zip(labels, cm):
        print(f"{label[:12]:14s}" + "".join(f"{v:14d}" for v in row))
 
    # Importancia de variables (solo tiene sentido tras el one-hot, asi
    # que se listan las NUMERICAS directamente -- las categoricas quedan
    # expandidas y son menos interpretables una a una)
    model = clf.named_steps["model"]
    feature_names = clf.named_steps["prep"].get_feature_names_out()
    importances = sorted(
        zip(feature_names, model.feature_importances_), key=lambda x: -x[1]
    )
    print("\n[+] Variables mas importantes (top 10):")
    for name, imp in importances[:10]:
        print(f"      {name:40s} {imp:.4f}")
 
 
if __name__ == "__main__":
    main()