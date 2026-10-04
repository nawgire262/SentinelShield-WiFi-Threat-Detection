import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt

# Load dataset
data = pd.read_csv("wifi_dataset.csv", on_bad_lines="skip")

# Remove unlabeled rows
data = data.dropna(subset=["Label"])
data = data[data["Label"] != ""]

if len(data) < 6:
    print("❌ Not enough data for evaluation")
    exit()

# Encode
le_security = LabelEncoder()
le_label = LabelEncoder()

data["Security"] = le_security.fit_transform(data["Security"])
data["Label"] = le_label.fit_transform(data["Label"])

# Features
X = data[["RSSI", "Channel", "Security", "AP_Count", "Signal_Var"]]
y = data["Label"]

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# Train models
rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    random_state=42
)
rf_model.fit(X_train, y_train)

knn_model = KNeighborsClassifier(n_neighbors=3)
knn_model.fit(X_train, y_train)

# Predict
rf_pred = rf_model.predict(X_test)
knn_pred = knn_model.predict(X_test)

# Accuracy
rf_acc = accuracy_score(y_test, rf_pred)
knn_acc = accuracy_score(y_test, knn_pred)

print(f"\n✅ Random Forest Accuracy: {rf_acc * 100:.2f}%")
print(f"✅ KNN Accuracy: {knn_acc * 100:.2f}%\n")

print("📊 Random Forest Classification Report:\n")
print(classification_report(y_test, rf_pred))

print("📊 KNN Classification Report:\n")
print(classification_report(y_test, knn_pred))

# Confusion matrices
rf_cm = confusion_matrix(y_test, rf_pred)
knn_cm = confusion_matrix(y_test, knn_pred)

print("📊 Random Forest Confusion Matrix:")
print(rf_cm)

print("\n📊 KNN Confusion Matrix:")
print(knn_cm)

# Plot RF confusion matrix
plt.figure()
plt.imshow(rf_cm)
plt.title("Random Forest Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")

for i in range(len(rf_cm)):
    for j in range(len(rf_cm)):
        plt.text(j, i, rf_cm[i][j], ha="center", va="center")

plt.show()

# Plot KNN confusion matrix
plt.figure()
plt.imshow(knn_cm)
plt.title("KNN Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")

for i in range(len(knn_cm)):
    for j in range(len(knn_cm)):
        plt.text(j, i, knn_cm[i][j], ha="center", va="center")

plt.show()