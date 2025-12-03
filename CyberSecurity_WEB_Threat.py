import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

df = pd.read_csv(r"C:\Users\HP\OneDrive\Desktop\CloudWatch_Traffic_Web_Attack.csv")

print(df.head(10))

print("\nINFO\n")
df.info()

print("\n(NUMERICAL SUMMARY) \n")
print(df.describe())

print("\nMISSING VALUES \n")
print(df.isnull().sum())

print("\nSHAPE OF DATA \n")
print("Rows:", df.shape[0])
print("Columns:", df.shape[1])

for col in ['creation_time', 'end_time', 'time']:
    if col in df.columns:
        df[col] = pd.to_datetime(df[col], errors='coerce')

for col in ['bytes_in', 'bytes_out']:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')

if 'creation_time' in df.columns and 'end_time' in df.columns:
    df['duration_seconds'] = (df['end_time'] - df['creation_time']).dt.total_seconds()

print("\n CLEANED DATA SAMPLE ")
print(df.head())

# EXPLORATORY DATA ANALYSIS 

if 'protocol' in df.columns:
    print("\n PROTOCOL COUNTS ")
    print(df['protocol'].value_counts())

    df['protocol'].value_counts().plot(kind='bar', figsize=(7,4))
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.show()

#  Source Country Distribution
if 'src_ip_country_code' in df.columns:
    print("\nTOP COUNTRIES ")
    print(df['src_ip_country_code'].value_counts().head(10))

    df['src_ip_country_code'].value_counts().head(10).plot(kind='bar', figsize=(7,4))
    plt.title("Top 10 Source Countries")
    plt.xlabel("Country Code")
    plt.ylabel("Count")
    plt.show()

# ---- Bytes_in and Bytes_out distributions ----
if 'bytes_in' in df.columns:
    df['bytes_in'].hist(bins=30, figsize=(7,4))
    plt.title("bytes_in Distribution")
    plt.xlabel("bytes_in")
    plt.ylabel("Frequency")
    plt.show()

if 'bytes_out' in df.columns:
    df['bytes_out'].hist(bins=30, figsize=(7,4))
    plt.title("bytes_out Distribution")
    plt.xlabel("bytes_out")
    plt.ylabel("Frequency")
    plt.show()

#  bytes_in vs bytes_out 
if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
    plt.figure(figsize=(7,4))
    plt.scatter(df['bytes_in'], df['bytes_out'], s=10)
    plt.title("bytes_in vs bytes_out")
    plt.xlabel("bytes_in")
    plt.ylabel("bytes_out")
    plt.show()

# Time Series 
if 'creation_time' in df.columns and not df['creation_time'].isna().all():
    hourly = df.set_index("creation_time").resample("1h")["bytes_in"].sum()


    plt.figure(figsize=(10,4))
    plt.plot(hourly)
    plt.title("Hourly Traffic (bytes_in)")
    plt.xlabel("Time")
    plt.ylabel("bytes_in")
    plt.show()

print("\nKEY INSIGHTS")

# Total traffic
if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
    print("Total Bytes In:", df['bytes_in'].sum())
    print("Total Bytes Out:", df['bytes_out'].sum())

# Average duration
if 'duration_seconds' in df.columns:
    print("Average Duration (seconds):", df['duration_seconds'].mean())

# Top attacking countries
if 'src_ip_country_code' in df.columns:
    print("\nMost frequent attacker country:",
          df['src_ip_country_code'].value_counts().idxmax())

if 'protocol' in df.columns:
    print("Most common protocol:",
          df['protocol'].value_counts().idxmax())

if 'detection_types' in df.columns:
    print("\nDetection types distribution:")
    print(df['detection_types'].value_counts())

numeric_df = df.select_dtypes(include=[np.number])

correlation_matrix_numeric = numeric_df.corr()

plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix_numeric,annot=True,fmt=".2f",cmap='coolwarm')

plt.title("Correlation Matrix Heatmap")
plt.show()

detection_types_by_country = pd.crosstab(df['src_ip_country_code'],df['detection_types'])

detection_types_by_country.plot(kind='bar',stacked=True,figsize=(12,6),colormap='tab20')

plt.title('Detection Types by Country Code')
plt.xlabel('Country Code')
plt.ylabel('Count of Detection Types')
plt.xticks(rotation=45)
plt.legend(title='Detection Type')
plt.tight_layout()
plt.show()

df['creation_time'] = pd.to_datetime(df['creation_time'])

df.set_index('creation_time', inplace=True)
plt.figure(figsize=(12, 6))
plt.plot(df.index, df['bytes_in'], label='Bytes In', marker='o')
plt.plot(df.index, df['bytes_out'], label='Bytes Out', marker='o')
plt.title('Web Traffic Analysis Over Time')
plt.xlabel('Time')
plt.ylabel('Bytes')
plt.legend()
plt.grid(True)
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

import networkx as nx

G = nx.Graph()

for idx, row in df.iterrows():
    G.add_edge(row['src_ip'], row['dst_ip'])
plt.figure(figsize=(14, 10))
nx.draw_networkx(G,with_labels=True,node_size=30,font_size=6,node_color='skyblue',font_color='darkblue')
plt.title('Network Interaction between Source and Destination IPs')
plt.axis('off')   
plt.show()

X = df.select_dtypes(include=['int64', 'float64'])

y = df['detection_types']
X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.3,random_state=42)
rf_classifier = RandomForestClassifier(n_estimators=100,random_state=42)
rf_classifier.fit(X_train, y_train)
y_pred = rf_classifier.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam

df['is_suspicious'] = (df['detection_types'] == 'waf_rule').astype(int)
X = df[['bytes_in', 'bytes_out']].values
y = df['is_suspicious'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)

# Normalize
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = Sequential([tf.keras.Input(shape=(X_train_scaled.shape[1],)),Dense(128, activation='relu'),Dropout(0.5),Dense(128, activation='relu'),Dropout(0.5),Dense(1, activation='sigmoid')])
model.compile(optimizer=Adam(), loss='binary_crossentropy', metrics=['accuracy'])
history = model.fit(X_train_scaled, y_train,epochs=10, batch_size=32, verbose=1,validation_split=0.2)
loss, accuracy = model.evaluate(X_test_scaled, y_test)
print(f"Test Accuracy: {accuracy*100:.2f}%")
plt.figure(figsize=(12, 6))
plt.subplot(1, 2, 1)
plt.plot(history.history['accuracy'], label='Training Accuracy')
plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
plt.title('Model Accuracy')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend()
plt.subplot(1, 2, 2)
plt.plot(history.history['loss'], label='Training Loss')
plt.plot(history.history['val_loss'], label='Validation Loss')
plt.title('Model Loss')
plt.xlabel('Epoch')
plt.ylabel('Loss')
plt.legend()
plt.show()
