import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# Load the dataset
file_path = "public/csv/mumbai_crime_data.csv"
data = pd.read_csv(file_path)

# Get all unique crime types before encoding
all_crime_types = list(data['crime_type'].unique()) + ["theft", "assault", "burglary", "fraud", "murder", "vandalism", "drugOffense", "domesticViolence"]

# Fit Label Encoder with all crime types
label_encoder = LabelEncoder()
label_encoder.fit(all_crime_types)

# Encode crime types
data['crime_type_encoded'] = label_encoder.transform(data['crime_type'])

# Extract relevant features from the user-selected date/time
data['date'] = pd.to_datetime(data['date'], dayfirst=True, errors='coerce')
data['hour'] = data['date'].dt.hour
data['day_of_week'] = data['date'].dt.dayofweek
data['month'] = data['date'].dt.month

# Define features and target variable
features = ['latitude', 'longitude', 'hour', 'day_of_week', 'month', 'crime_type_encoded']
target = 'crime_type_encoded'

X = data[features]
y = data[target]

# Split dataset into training & testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)


# Save model, label encoder & feature names
joblib.dump(model, "public/pkl/crime_prediction_model.pkl")
joblib.dump(label_encoder, "public/pkl/label_encoder.pkl")
joblib.dump(features, "public/pkl/feature_names.pkl")  # Save feature names for consistency

print("Model trained and saved successfully!")
