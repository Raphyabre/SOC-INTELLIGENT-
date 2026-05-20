# ================================================================
#   🛡️  SOC INTELLIGENT — DÉTECTION D'INTRUSIONS RÉSEAU PAR IA
#   Dataset  : NSL-KDD (125 000+ connexions réseau)
#   Modèles  : Random Forest + XGBoost + DNN + LSTM Autoencoder
#   Auteur   : Projet de fin de module — IA & Cybersécurité
# ================================================================
#
#  Exécution directe  : python soc_notebook.py
#  Conversion Jupyter : jupytext --to notebook soc_notebook.py
#
# ================================================================

# ── Imports ──────────────────────────────────────────────────────
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
import warnings
import time
import random
import os
import json
from collections import Counter

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import xgboost as xgb
import joblib

import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import (
    Dense, Dropout, LSTM, Input,
    RepeatVector, TimeDistributed, BatchNormalization
)
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam

warnings.filterwarnings('ignore')
tf.get_logger().setLevel('ERROR')

# ── Style matplotlib (thème SOC dark) ────────────────────────────
DARK    = '#0d1117'
MID     = '#161b22'
BORDER  = '#30363d'
ACCENT  = '#58a6ff'
SUCCESS = '#3fb950'
DANGER  = '#f85149'
WARN    = '#d29922'
PURPLE  = '#bc8cff'
TEXT    = '#c9d1d9'

plt.rcParams.update({
    'figure.facecolor': DARK,
    'axes.facecolor':   MID,
    'axes.edgecolor':   BORDER,
    'axes.labelcolor':  TEXT,
    'text.color':       TEXT,
    'xtick.color':      TEXT,
    'ytick.color':      TEXT,
    'grid.color':       BORDER,
    'grid.alpha':       0.4,
    'figure.dpi':       120,
    'font.size':        10,
    'axes.titlesize':   11,
    'axes.titlepad':    10,
})

# ── Constantes ────────────────────────────────────────────────────
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

ATTACK_CAT = {
    'normal'          : 'NORMAL',
    # DoS
    'back'            : 'DoS', 'land'          : 'DoS', 'neptune'   : 'DoS',
    'pod'             : 'DoS', 'smurf'         : 'DoS', 'teardrop'  : 'DoS',
    'apache2'         : 'DoS', 'udpstorm'      : 'DoS', 'processtable': 'DoS', 'worm': 'DoS',
    # Probe
    'ipsweep'         : 'Probe', 'nmap'         : 'Probe', 'portsweep': 'Probe',
    'satan'           : 'Probe', 'mscan'        : 'Probe', 'saint'    : 'Probe',
    # R2L
    'ftp_write'       : 'R2L', 'guess_passwd'  : 'R2L', 'imap'      : 'R2L',
    'multihop'        : 'R2L', 'phf'           : 'R2L', 'spy'       : 'R2L',
    'warezclient'     : 'R2L', 'warezmaster'   : 'R2L', 'sendmail'  : 'R2L',
    'named'           : 'R2L', 'snmpgetattack' : 'R2L', 'snmpguess' : 'R2L',
    'xlock'           : 'R2L', 'xsnoop'        : 'R2L', 'httptunnel': 'R2L',
    # U2R
    'buffer_overflow' : 'U2R', 'loadmodule'    : 'U2R', 'perl'      : 'U2R',
    'rootkit'         : 'U2R', 'mailbomb'      : 'U2R', 'ps'        : 'U2R',
    'sqlattack'       : 'U2R', 'xterm'         : 'U2R',
}

CAT_COLORS = {
    'NORMAL': SUCCESS, 'DoS': DANGER,
    'Probe': WARN, 'R2L': '#f0883e', 'U2R': PURPLE
}

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

CAT_FEATURES = ['protocol_type', 'service', 'flag']

os.makedirs('models',  exist_ok=True)
os.makedirs('figures', exist_ok=True)


# ════════════════════════════════════════════════════════════════
#   SECTION 1 : COMPRENDRE LES DONNÉES
# ════════════════════════════════════════════════════════════════
print("\n╔══════════════════════════════════════════════════════════════╗")
print("║   🛡️  SOC INTELLIGENT — DÉTECTION D'INTRUSIONS PAR IA      ║")
print("╠══════════════════════════════════════════════════════════════╣")
print(f"║  TensorFlow : {tf.__version__:<47}║")
print("║  Modèles    : RF + XGBoost + DNN + LSTM Autoencoder         ║")
print("╚══════════════════════════════════════════════════════════════╝")

print("\n" + "═"*65)
print("  SECTION 1 : COMPRENDRE LES DONNÉES")
print("═"*65)

print("\n📥 Chargement du dataset NSL-KDD depuis GitHub...")
df_train = pd.read_csv(TRAIN_URL, header=None, names=COLUMNS)
df_test  = pd.read_csv(TEST_URL,  header=None, names=COLUMNS)

for df in [df_train, df_test]:
    df.drop('difficulty_level', axis=1, inplace=True)
    df['label_binary'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
    df['label_cat']    = df['label'].map(ATTACK_CAT).fillna('Other')

print(f"\n  {'Ensemble':<10} {'Lignes':>10} {'Colonnes':>10}")
print(f"  {'─'*32}")
print(f"  {'Train':<10} {df_train.shape[0]:>10,} {df_train.shape[1]:>10}")
print(f"  {'Test':<10}  {df_test.shape[0]:>10,}  {df_test.shape[1]:>10}")

print(f"\n  Types de colonnes :")
print(f"    Numériques   : {df_train.select_dtypes(include=np.number).shape[1]}")
print(f"    Catégoriels  : {df_train.select_dtypes(include='object').shape[1]}")

print(f"\n  Features catégorielles : {CAT_FEATURES}")
print(f"  Variable cible         : 'label' (binaire + catégorielle)")
print(f"\n  Valeurs manquantes : {df_train.isnull().sum().sum()}")
print(f"  Doublons           : {df_train.duplicated().sum()}")

# Distribution des attaques
print(f"\n  Distribution des catégories (train) :")
cat_counts = df_train['label_cat'].value_counts()
total = len(df_train)
for cat, count in cat_counts.items():
    bar = '█' * int(28 * count / total)
    color_tag = cat
    print(f"    {cat:<8} {count:>6,}  {100*count/total:5.1f}%  {bar}")

print(f"\n  Attaques binaires :")
bc = df_train['label_binary'].value_counts()
print(f"    Normal  : {bc.get(0, 0):>6,}  ({100*bc.get(0,0)/total:.1f}%)")
print(f"    Attaque : {bc.get(1, 0):>6,}  ({100*bc.get(1,0)/total:.1f}%)")

# ── Visualisations Section 1 ──────────────────────────────────────
print("\n📊 Génération des visualisations Section 1...")
fig = plt.figure(figsize=(18, 10), facecolor=DARK)
fig.suptitle('Section 1 — Analyse exploratoire du dataset NSL-KDD',
             color=TEXT, fontsize=14, fontweight='bold', y=1.01)

gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.5, wspace=0.38)

# 1a : Distribution catégories
ax1 = fig.add_subplot(gs[0, 0])
colors_cat = [CAT_COLORS.get(c, ACCENT) for c in cat_counts.index]
bars = ax1.bar(cat_counts.index, cat_counts.values,
               color=colors_cat, edgecolor=BORDER, width=0.6)
ax1.set_title('Distribution des catégories', color=TEXT)
ax1.set_ylabel('Connexions')
for bar, val in zip(bars, cat_counts.values):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 200,
             f'{val:,}', ha='center', fontsize=8, color=TEXT)

# 1b : Protocoles vs trafic
ax2 = fig.add_subplot(gs[0, 1])
proto = df_train.groupby('protocol_type')['label_binary'].agg(['sum','count']).reset_index()
proto.columns = ['proto', 'attack', 'total']
proto['normal'] = proto['total'] - proto['attack']
x_p = np.arange(len(proto))
ax2.bar(x_p - 0.2, proto['normal'],  0.38, label='Normal',  color=SUCCESS, edgecolor=BORDER)
ax2.bar(x_p + 0.2, proto['attack'],  0.38, label='Attaque', color=DANGER,  edgecolor=BORDER)
ax2.set_xticks(x_p); ax2.set_xticklabels(proto['proto'])
ax2.set_title('Protocoles — Normal vs Attaque', color=TEXT)
ax2.legend(facecolor=MID, edgecolor=BORDER, labelcolor=TEXT)

# 1c : Top 10 labels
ax3 = fig.add_subplot(gs[0, 2])
top10 = df_train['label'].value_counts().head(10)
c10 = [SUCCESS if l == 'normal' else DANGER for l in top10.index]
ax3.barh(top10.index[::-1], top10.values[::-1], color=c10[::-1],
         edgecolor=BORDER, height=0.65)
ax3.set_title("Top 10 types d'attaques", color=TEXT)
ax3.set_xlabel('Occurrences')

# 1d : Heatmap corrélation
ax4 = fig.add_subplot(gs[1, :2])
num_cols = df_train.select_dtypes(include=np.number).drop(
    columns=['label_binary'], errors='ignore').columns[:14]
corr = df_train[num_cols].corr()
sns.heatmap(corr, ax=ax4, cmap='RdBu_r', center=0,
            annot=False, linewidths=0.3, vmin=-1, vmax=1,
            cbar_kws={'shrink': 0.75})
ax4.set_title('Matrice de corrélation (14 features numériques)', color=TEXT)
ax4.tick_params(axis='x', rotation=45, labelsize=8)
ax4.tick_params(axis='y', labelsize=8)

# 1e : Train vs Test
ax5 = fig.add_subplot(gs[1, 2])
categories_list = cat_counts.index.tolist()
train_v = [df_train[df_train['label_cat'] == c].shape[0] for c in categories_list]
test_v  = [df_test[df_test['label_cat'] == c].shape[0]   for c in categories_list]
xv = np.arange(len(categories_list))
ax5.bar(xv - 0.2, train_v, 0.38, label='Train', color=ACCENT,   alpha=0.85, edgecolor=BORDER)
ax5.bar(xv + 0.2, test_v,  0.38, label='Test',  color='#f778ba', alpha=0.85, edgecolor=BORDER)
ax5.set_xticks(xv); ax5.set_xticklabels(categories_list, fontsize=8)
ax5.set_title('Train vs Test par catégorie', color=TEXT)
ax5.legend(facecolor=MID, edgecolor=BORDER, labelcolor=TEXT)

plt.savefig('figures/section1_eda.png', bbox_inches='tight', facecolor=DARK, dpi=120)
plt.show()
print("  ✅ figures/section1_eda.png")


# ════════════════════════════════════════════════════════════════
#   SECTION 2 : PRÉPARATION DES DONNÉES
# ════════════════════════════════════════════════════════════════
print("\n" + "═"*65)
print("  SECTION 2 : PRÉPARATION DES DONNÉES")
print("═"*65)

FEATURE_COLS = [c for c in df_train.columns
                if c not in ('label', 'label_binary', 'label_cat')]

# LabelEncoder sur chaque feature catégorielle
# On fit sur l'union train+test pour éviter les unseen labels
le_features = {}
for feat in CAT_FEATURES:
    le_features[feat] = LabelEncoder()
    all_vals = pd.concat([df_train[feat], df_test[feat]])
    le_features[feat].fit(all_vals)
    df_train[feat] = le_features[feat].transform(df_train[feat])
    df_test[feat]  = le_features[feat].transform(df_test[feat])

print(f"  ✅ LabelEncoder appliqué : {CAT_FEATURES}")

# Encoder la variable cible (multiclasse)
le_cat = LabelEncoder()
all_cats = pd.concat([df_train['label_cat'], df_test['label_cat']])
le_cat.fit(all_cats)

# Matrices X / vecteurs y
X_all       = df_train[FEATURE_COLS].values
y_bin_all   = df_train['label_binary'].values
y_cat_all   = le_cat.transform(df_train['label_cat'])
n_classes   = len(le_cat.classes_)

X_test_raw  = df_test[FEATURE_COLS].values
y_test_bin  = df_test['label_binary'].values
y_test_cat  = le_cat.transform(df_test['label_cat'])

# Split stratifié 80/20
X_train, X_val, y_train_bin, y_val_bin, y_train_cat, y_val_cat = \
    train_test_split(X_all, y_bin_all, y_cat_all,
                     test_size=0.2, random_state=42, stratify=y_bin_all)

# Normalisation (StandardScaler)
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_val_s   = scaler.transform(X_val)
X_test_s  = scaler.transform(X_test_raw)

n_features = X_train_s.shape[1]

print(f"\n  Division train/val/test :")
print(f"    Train  : {X_train.shape[0]:>7,} ({100*(1-0.2):.0f}%) — {X_train.shape[1]} features")
print(f"    Val    : {X_val.shape[0]:>7,} ({100*0.2:.0f}%)")
print(f"    Test   : {X_test_s.shape[0]:>7,} (NSL-KDD Test+)")
print(f"\n  Classes ({n_classes}) : {', '.join(le_cat.classes_)}")
print(f"  Normalisation : StandardScaler (μ=0, σ=1)")

# Sauvegarder encodeurs + scaler
joblib.dump(scaler,       'models/scaler.pkl')
joblib.dump(le_cat,       'models/le_cat.pkl')
joblib.dump(le_features,  'models/le_features.pkl')
joblib.dump(FEATURE_COLS, 'models/feature_cols.pkl')
print(f"\n  ✅ Artefacts sauvegardés dans models/")


# ════════════════════════════════════════════════════════════════
#   SECTION 3 : MODÈLES DE DÉTECTION
# ════════════════════════════════════════════════════════════════
print("\n" + "═"*65)
print("  SECTION 3 : MODÈLES DE DÉTECTION")
print("═"*65)

results = {}   # Stockage des métriques pour comparaison finale

def evaluate_model(name, y_true, y_pred):
    """Calcule et affiche toutes les métriques demandées."""
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    rec  = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    f1   = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    cm   = confusion_matrix(y_true, y_pred)

    print(f"\n  ┌─ {name}")
    print(f"  │  Accuracy        : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  │  Précision       : {prec:.4f}")
    print(f"  │  Recall          : {rec:.4f}")
    print(f"  │  F1-Score        : {f1:.4f}")
    print(f"  │  Matrice         : {cm.shape}")
    print(f"  └─ Rapport complet :")
    print(classification_report(y_true, y_pred, zero_division=0,
                                target_names=['Normal', 'Attaque']))

    return {'accuracy': acc, 'precision': prec, 'recall': rec,
            'f1': f1, 'cm': cm, 'name': name}


# ── 3.1 : Random Forest ──────────────────────────────────────────
print("\n── 3.1  Random Forest ──────────────────────────────────────")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    n_jobs=-1,
    random_state=42,
    class_weight='balanced'
)
t0 = time.time()
rf.fit(X_train_s, y_train_bin)
rf_time = time.time() - t0

y_pred_rf = rf.predict(X_test_s)
print(f"  Temps d'entraînement : {rf_time:.2f}s")
results['Random Forest'] = evaluate_model('Random Forest', y_test_bin, y_pred_rf)
results['Random Forest']['train_time'] = rf_time
results['Random Forest']['fi']         = rf.feature_importances_

joblib.dump(rf, 'models/random_forest.pkl')
print("  💾 models/random_forest.pkl")


# ── 3.2 : XGBoost ────────────────────────────────────────────────
print("\n── 3.2  XGBoost ────────────────────────────────────────────")
scale_pos = float((y_train_bin == 0).sum() / max((y_train_bin == 1).sum(), 1))
xgb_model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric='logloss',
    n_jobs=-1,
    random_state=42,
    scale_pos_weight=scale_pos,
    verbosity=0
)
t0 = time.time()
xgb_model.fit(X_train_s, y_train_bin,
              eval_set=[(X_val_s, y_val_bin)],
              verbose=False)
xgb_time = time.time() - t0

y_pred_xgb = xgb_model.predict(X_test_s)
print(f"  Temps d'entraînement : {xgb_time:.2f}s")
results['XGBoost'] = evaluate_model('XGBoost', y_test_bin, y_pred_xgb)
results['XGBoost']['train_time'] = xgb_time

joblib.dump(xgb_model, 'models/xgboost.pkl')
print("  💾 models/xgboost.pkl")


# ── 3.3 : Deep Neural Network (DNN) ──────────────────────────────
print("\n── 3.3  Deep Neural Network (DNN) ──────────────────────────")
dnn = Sequential([
    Dense(256, activation='relu', input_shape=(n_features,), name='fc1'),
    BatchNormalization(),
    Dropout(0.35),
    Dense(128, activation='relu', name='fc2'),
    BatchNormalization(),
    Dropout(0.3),
    Dense(64, activation='relu', name='fc3'),
    BatchNormalization(),
    Dropout(0.2),
    Dense(32, activation='relu', name='fc4'),
    Dense(1, activation='sigmoid', name='output')
], name='DNN_SOC')

dnn.compile(optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy'])
dnn.summary()

callbacks_dnn = [
    EarlyStopping(patience=6, restore_best_weights=True,
                  monitor='val_loss', verbose=0),
]
t0 = time.time()
history_dnn = dnn.fit(
    X_train_s, y_train_bin,
    validation_data=(X_val_s, y_val_bin),
    epochs=60, batch_size=512,
    callbacks=callbacks_dnn, verbose=1
)
dnn_time = time.time() - t0

y_prob_dnn = dnn.predict(X_test_s, verbose=0).ravel()
y_pred_dnn = (y_prob_dnn > 0.5).astype(int)

print(f"\n  Temps d'entraînement : {dnn_time:.2f}s  |  Époques : {len(history_dnn.history['loss'])}")
results['DNN'] = evaluate_model('DNN', y_test_bin, y_pred_dnn)
results['DNN']['train_time'] = dnn_time
results['DNN']['history']    = history_dnn.history

dnn.save('models/dnn_model.keras')
print("  💾 models/dnn_model.keras")


# ── 3.4 : LSTM Autoencoder (détection d'anomalies) ───────────────
print("\n── 3.4  LSTM Autoencoder — Détection d'anomalies ───────────")
print("  (Entraîné UNIQUEMENT sur le trafic NORMAL — approche non supervisée)")

# On sélectionne uniquement les échantillons normaux pour l'entraînement
X_normal_train = X_train_s[y_train_bin == 0]
X_normal_val   = X_val_s[y_val_bin == 0]
print(f"  Normaux train : {X_normal_train.shape[0]:,}  |  Normaux val : {X_normal_val.shape[0]:,}")

# Reshape : (samples, timesteps=1, features) — chaque sample = 1 séquence temporelle
X_normal_train_r = X_normal_train.reshape(-1, 1, n_features)
X_normal_val_r   = X_normal_val.reshape(-1, 1, n_features)
X_test_r         = X_test_s.reshape(-1, 1, n_features)

# Architecture LSTM Autoencoder
inp      = Input(shape=(1, n_features), name='input')
# Encoder
enc      = LSTM(64, return_sequences=False, name='encoder_lstm')(inp)
bottleneck = Dense(32, activation='relu', name='bottleneck')(enc)
# Decoder
dec      = RepeatVector(1, name='repeat')(bottleneck)
dec      = LSTM(64, return_sequences=True, name='decoder_lstm')(dec)
out      = TimeDistributed(Dense(n_features), name='reconstruction')(dec)

autoencoder = Model(inp, out, name='LSTM_Autoencoder_SOC')
autoencoder.compile(optimizer=Adam(0.001), loss='mse')
autoencoder.summary()

callbacks_ae = [
    EarlyStopping(patience=5, restore_best_weights=True, monitor='val_loss', verbose=0)
]
t0 = time.time()
history_ae = autoencoder.fit(
    X_normal_train_r, X_normal_train_r,
    validation_data=(X_normal_val_r, X_normal_val_r),
    epochs=30, batch_size=512,
    callbacks=callbacks_ae, verbose=1
)
ae_time = time.time() - t0

# Calcul du seuil d'anomalie (μ + 2σ sur la validation normale)
val_recon  = autoencoder.predict(X_normal_val_r, verbose=0)
val_errors = np.mean(np.power(X_normal_val_r - val_recon, 2), axis=(1, 2))
THRESHOLD  = float(np.mean(val_errors) + 2 * np.std(val_errors))
print(f"\n  Seuil d'anomalie (μ+2σ) : {THRESHOLD:.6f}")

# Prédiction sur le test set
test_recon  = autoencoder.predict(X_test_r, verbose=0)
test_errors = np.mean(np.power(X_test_r - test_recon, 2), axis=(1, 2))
y_pred_ae   = (test_errors > THRESHOLD).astype(int)

print(f"  Temps d'entraînement : {ae_time:.2f}s  |  Époques : {len(history_ae.history['loss'])}")
results['LSTM Autoencoder'] = evaluate_model('LSTM Autoencoder', y_test_bin, y_pred_ae)
results['LSTM Autoencoder']['train_time'] = ae_time
results['LSTM Autoencoder']['threshold']  = THRESHOLD
results['LSTM Autoencoder']['history']    = history_ae.history
results['LSTM Autoencoder']['errors']     = test_errors.tolist()

autoencoder.save('models/lstm_autoencoder.keras')
np.save('models/ae_threshold.npy', np.array([THRESHOLD]))
print("  💾 models/lstm_autoencoder.keras")
print(f"  💾 models/ae_threshold.npy  (seuil = {THRESHOLD:.6f})")


# ── Visualisations Section 3 ──────────────────────────────────────
print("\n📊 Génération des visualisations Section 3...")

fig2, axes = plt.subplots(2, 3, figsize=(18, 11), facecolor=DARK)
fig2.suptitle('Section 3 — Évaluation et Comparaison des Modèles',
              color=TEXT, fontsize=14, fontweight='bold')

model_names = list(results.keys())
metrics_k   = ['accuracy', 'precision', 'recall', 'f1']
m_labels    = ['Accuracy', 'Précision', 'Recall', 'F1-Score']
colors_m    = [ACCENT, SUCCESS, WARN, PURPLE]

# 3a : Barres métriques comparatives
ax = axes[0, 0]
x  = np.arange(len(metrics_k))
w  = 0.2
for i, (name, col) in enumerate(zip(model_names, colors_m)):
    vals = [results[name][mk] for mk in metrics_k]
    ax.bar(x + (i - 1.5)*w, vals, w, label=name,
           color=col, alpha=0.85, edgecolor=BORDER)
ax.set_xticks(x); ax.set_xticklabels(m_labels)
ax.set_ylim(0.70, 1.02)
ax.set_title('Métriques par modèle', color=TEXT)
ax.legend(facecolor=MID, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
ax.yaxis.grid(True, alpha=0.3)

# 3b : Temps d'entraînement
ax = axes[0, 1]
times = [results[n]['train_time'] for n in model_names]
brs   = ax.bar(model_names, times, color=colors_m, edgecolor=BORDER, width=0.55)
ax.set_title("Temps d'entraînement (secondes)", color=TEXT)
for b, t in zip(brs, times):
    ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.5,
            f'{t:.1f}s', ha='center', color=TEXT, fontsize=9)
ax.tick_params(axis='x', rotation=12)

# 3c : Courbe apprentissage DNN
ax = axes[0, 2]
h  = results['DNN']['history']
ax.plot(h['accuracy'],     color=ACCENT,   lw=1.5, label='Train Acc')
ax.plot(h['val_accuracy'], color=SUCCESS,   lw=1.5, label='Val Acc')
ax.plot(h['loss'],         color=DANGER,   lw=1.2, ls='--', label='Train Loss')
ax.plot(h['val_loss'],     color='#f778ba', lw=1.2, ls='--', label='Val Loss')
ax.set_title('Courbe apprentissage — DNN', color=TEXT)
ax.legend(facecolor=MID, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
ax.set_xlabel('Époque')

# 3d : Matrice de confusion — Random Forest
ax = axes[1, 0]
cm_rf = results['Random Forest']['cm']
sns.heatmap(cm_rf, annot=True, fmt='d', ax=ax, cmap='Blues', cbar=False,
            xticklabels=['Normal','Attaque'],
            yticklabels=['Normal','Attaque'],
            annot_kws={'size': 12})
ax.set_title('Matrice confusion — Random Forest', color=TEXT)
ax.set_xlabel('Prédit'); ax.set_ylabel('Réel')

# 3e : Matrice de confusion — XGBoost
ax = axes[1, 1]
cm_xgb = results['XGBoost']['cm']
sns.heatmap(cm_xgb, annot=True, fmt='d', ax=ax, cmap='Greens', cbar=False,
            xticklabels=['Normal','Attaque'],
            yticklabels=['Normal','Attaque'],
            annot_kws={'size': 12})
ax.set_title('Matrice confusion — XGBoost', color=TEXT)
ax.set_xlabel('Prédit'); ax.set_ylabel('Réel')

# 3f : LSTM AE — Loss + distribution des erreurs
ax = axes[1, 2]
h_ae = results['LSTM Autoencoder']['history']
ax.plot(h_ae['loss'],     color=ACCENT, lw=1.5, label='Train MSE')
ax.plot(h_ae['val_loss'], color=SUCCESS, lw=1.5, label='Val MSE')
ax.axhline(y=THRESHOLD, color=DANGER, ls='--', lw=1.5,
           label=f'Seuil = {THRESHOLD:.4f}')
ax.set_title('LSTM Autoencoder — Loss + Seuil', color=TEXT)
ax.legend(facecolor=MID, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
ax.set_xlabel('Époque'); ax.set_ylabel('MSE')

plt.tight_layout()
plt.savefig('figures/section3_models.png', bbox_inches='tight', facecolor=DARK, dpi=120)
plt.show()
print("  ✅ figures/section3_models.png")

# Feature importance — Random Forest
fig3, ax_fi = plt.subplots(figsize=(12, 9), facecolor=DARK)
fi_vals  = results['Random Forest']['fi']
fi_idx   = np.argsort(fi_vals)[-20:]
fi_names = [FEATURE_COLS[i] for i in fi_idx]
fi_cols  = [ACCENT if fi_vals[i] > np.percentile(fi_vals, 75) else '#484f58'
            for i in fi_idx]

ax_fi.barh(fi_names, fi_vals[fi_idx], color=fi_cols,
           edgecolor=BORDER, height=0.72)
ax_fi.axvline(np.mean(fi_vals[fi_idx]), color=DANGER, ls='--', lw=1.2,
              alpha=0.8, label='Moyenne')
ax_fi.set_title('Top 20 features — Random Forest (importances)',
                color=TEXT, fontsize=12, pad=12)
ax_fi.set_xlabel('Importance relative')
ax_fi.legend(facecolor=MID, edgecolor=BORDER, labelcolor=TEXT)
plt.tight_layout()
plt.savefig('figures/section3_feature_importance.png', bbox_inches='tight',
            facecolor=DARK, dpi=120)
plt.show()
print("  ✅ figures/section3_feature_importance.png")

# Sauvegarde résultats JSON (pour le dashboard Streamlit)
results_json = {}
for k, v in results.items():
    results_json[k] = {
        'accuracy':   float(v['accuracy']),
        'precision':  float(v['precision']),
        'recall':     float(v['recall']),
        'f1':         float(v['f1']),
        'train_time': float(v['train_time']),
        'cm':         v['cm'].tolist(),
    }
with open('models/results.json', 'w') as f:
    json.dump(results_json, f, indent=2)
print("  ✅ models/results.json")


# ════════════════════════════════════════════════════════════════
#   SECTION 4 : SIMULATION TEMPS RÉEL
# ════════════════════════════════════════════════════════════════
print("\n" + "═"*65)
print("  SECTION 4 : SIMULATION TEMPS RÉEL")
print("═"*65)

def predict_ensemble(x_scaled):
    """
    Vote pondéré entre tous les modèles.
    Retourne : (label, score, détail des prédictions)
    """
    p_rf  = float(rf.predict_proba(x_scaled.reshape(1, -1))[0, 1])
    p_xgb = float(xgb_model.predict_proba(x_scaled.reshape(1, -1))[0, 1])
    p_dnn = float(dnn.predict(x_scaled.reshape(1, -1), verbose=0).ravel()[0])

    # LSTM Autoencoder : normaliser l'erreur de reconstruction → [0, 1]
    x_lstm = x_scaled.reshape(1, 1, -1)
    recon  = autoencoder.predict(x_lstm, verbose=0)
    error  = float(np.mean(np.power(x_lstm - recon, 2)))
    p_ae   = min(error / (THRESHOLD + 1e-9), 1.0)

    # Score pondéré (RF=35%, XGB=35%, DNN=20%, AE=10%)
    score = 0.35*p_rf + 0.35*p_xgb + 0.20*p_dnn + 0.10*p_ae

    is_attack = score > 0.50
    label     = 'ATTACK DETECTED 🚨' if is_attack else 'NORMAL         ✅'
    conf      = score if is_attack else 1 - score

    return label, conf, score, {'RF': p_rf, 'XGB': p_xgb, 'DNN': p_dnn, 'AE_norm': p_ae}


print("\n  🔴 DÉMARRAGE DE LA SIMULATION (50 événements)")
print("  Ensemble : RF(35%) + XGB(35%) + DNN(20%) + LSTM-AE(10%)\n")
print("─" * 80)
print(f"  {'#':>3}  {'Timestamp':<20}  {'Résultat':<22}  {'Score':>7}  {'Détail scores'}")
print("─" * 80)

N_EVENTS = 50
sample_idx = np.random.choice(len(X_test_s), N_EVENTS, replace=False)

event_log   = []
attack_cnt  = 0
normal_cnt  = 0

for i, idx in enumerate(sample_idx):
    x_s        = X_test_s[idx]
    true_label = 'ATTACK' if y_test_bin[idx] == 1 else 'NORMAL'

    label, conf, score, detail = predict_ensemble(x_s)
    is_atk = 'ATTACK' in label

    if is_atk:
        attack_cnt += 1
    else:
        normal_cnt += 1

    ts = f"2025-06-{(i // 48) + 1:02d} {(i % 24):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"
    detail_str = (f"RF:{detail['RF']:.2f} XGB:{detail['XGB']:.2f} "
                  f"DNN:{detail['DNN']:.2f} AE:{detail['AE_norm']:.2f}")

    print(f"  {i+1:>3}  {ts:<20}  {label:<22}  {score:>6.3f}  {detail_str}")

    event_log.append({
        'id': i + 1, 'timestamp': ts, 'label': 'ATTACK' if is_atk else 'NORMAL',
        'score': round(score, 4), 'confidence': round(conf, 4),
        'true': true_label, 'is_attack': int(is_atk),
        **{k: round(v, 4) for k, v in detail.items()}
    })

    time.sleep(0.04)

print("─" * 80)
print(f"\n  📊 RÉSUMÉ DE LA SIMULATION")
print(f"     Événements analysés : {N_EVENTS}")
print(f"     ✅ Normaux           : {normal_cnt}  ({100*normal_cnt/N_EVENTS:.1f}%)")
print(f"     🚨 Attaques          : {attack_cnt}  ({100*attack_cnt/N_EVENTS:.1f}%)")

# Sauvegarder le log pour le dashboard
with open('models/event_log.json', 'w') as f:
    json.dump(event_log, f, indent=2)
print(f"\n  ✅ models/event_log.json sauvegardé")


# ════════════════════════════════════════════════════════════════
#   SECTION 5 : INSTRUCTIONS DASHBOARD
# ════════════════════════════════════════════════════════════════
print("\n" + "═"*65)
print("  SECTION 5 : VISUALISATION — STREAMLIT DASHBOARD")
print("═"*65)
print("""
  Le dashboard Streamlit est dans le fichier streamlit_app.py

  Pour le lancer :
  ┌─────────────────────────────────────────────┐
  │  streamlit run streamlit_app.py             │
  └─────────────────────────────────────────────┘

  Fonctionnalités du dashboard :
  • 📡 Simulation live avec alertes en temps réel
  • 📊 Vue d'ensemble du dataset NSL-KDD
  • 🤖 Comparaison des 4 modèles (radar + barres)
  • 🔍 Feature importance interactive

  Tous les modèles ont été sauvegardés dans models/
""")

print("═"*65)
print("  ✅ PROJET COMPLET — Tous les modèles sont prêts !")
print("  📂 Structure :")
for f in sorted(os.listdir('models')):
    size = os.path.getsize(f'models/{f}')
    print(f"      models/{f}  ({size:,} octets)")
print("═"*65)