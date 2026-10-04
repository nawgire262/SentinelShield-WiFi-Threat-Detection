import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# Load dataset
data = pd.read_csv("wifi_dataset.csv")

# Encode categorical data
le_ssid = LabelEncoder()
le_security = LabelEncoder()
le_label = LabelEncoder()

data['SSID'] = le_ssid.fit_transform(data['SSID'])
data['Security'] = le_security.fit_transform(data['Security'])
data['Label'] = le_label.fit_transform(data['Label'])

# Features & target
X = data[['RSSI', 'Channel', 'Security', 'AP_Count', 'Signal_Var']]
y = data['Label']

# Train model
model = RandomForestClassifier()
model.fit(X, y)

print("✅ Model Trained Successfully!")

# Test sample
sample = pd.DataFrame([{
    'SSID': le_ssid.transform(['Raj'])[0],
    'RSSI': -30,
    'Channel': 11,
    'Security': le_security.transform(['Open'])[0]
}])

prediction = model.predict(sample)

if prediction[0] == 1:
    print("⚠️ Fake WiFi Detected (ML)")
else:
    print("✅ Legit WiFi (ML)")