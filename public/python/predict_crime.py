import pandas as pd
import numpy as np
import os
import sys
import json
import joblib
import geopandas as gpd
from shapely.geometry import Point, shape
from sklearn.preprocessing import MinMaxScaler

# Load trained model and label encoder
model_path = "public/pkl/crime_prediction_model.pkl"
encoder_path = "public/pkl/label_encoder.pkl"
features_path = "public/pkl/feature_names.pkl"

model = joblib.load(model_path)
label_encoder = joblib.load(encoder_path)
feature_names = joblib.load(features_path)

# Load Mumbai boundary from GeoJSON
geojson_path = "public/geojson/Police_Station_Jurdition.geojson"
mumbai_boundary = gpd.read_file(geojson_path)
mumbai_polygon = shape(mumbai_boundary.geometry.unary_union)

# Generate a grid of locations across Mumbai
num_points = 20
latitudes = np.linspace(18.89, 19.3, num_points)
longitudes = np.linspace(72.74, 72.99, num_points)

# Read input arguments
crime_type = sys.argv[1]
selected_date = sys.argv[2]
selected_time = sys.argv[3]  # Format: HH:MM

# Convert date and time
selected_datetime = pd.to_datetime(f"{selected_date} {selected_time}", format="%Y-%m-%d %H:%M")
hour = selected_datetime.hour
day_of_week = selected_datetime.dayofweek
month = selected_datetime.month

if crime_type not in label_encoder.classes_:
    raise ValueError(f"Unknown crime type: {crime_type}. Please retrain the model with this category.")

# Encode crime type
try:
    crime_type_encoded = label_encoder.transform([crime_type])[0]
except ValueError:
    print(json.dumps({"error": f"Crime type '{crime_type}' not recognized. Retrain the model."}))
    sys.exit(1)


# Generate prediction data, filtering by Mumbai jurisdiction
prediction_data = []
for lat in latitudes:
    for lon in longitudes:
        point = Point(lon, lat)  # Create a point (longitude first for Shapely)
        if mumbai_polygon.contains(point):  # Keep only points inside Mumbai
            prediction_data.append([lat, lon, hour, day_of_week, month, crime_type_encoded])

# Convert to DataFrame with correct feature names
prediction_df = pd.DataFrame(prediction_data, columns=feature_names)

# Ensure all expected features exist
missing_features = set(feature_names) - set(prediction_df.columns)
if missing_features:
    raise ValueError(f"Missing features in prediction data: {missing_features}")

# Predict crime probability
predicted_probabilities = model.predict_proba(prediction_df)[:, 1]

# Scale probability to enhance visibility
from sklearn.preprocessing import MinMaxScaler

scaler = MinMaxScaler(feature_range=(0.1, 1))  # Scale between 0.1 and 1
scaled_probabilities = scaler.fit_transform(predicted_probabilities.reshape(-1, 1)).flatten()

# scaled_probabilities = np.clip(predicted_probabilities * 5, 0, 1)  # Multiply by 5 but cap at 1

# Format results
results = [
    {"latitude": lat, "longitude": lon, "crime_probability": round(prob, 2)}
    for (lat, lon, prob) in zip(prediction_df["latitude"], prediction_df["longitude"], scaled_probabilities)
]

# Output JSON properly
print(json.dumps(results))
