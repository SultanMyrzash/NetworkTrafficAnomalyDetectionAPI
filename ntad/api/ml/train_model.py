# train_model.py
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification

# Generate a synthetic dataset (replace with your actual dataset)
X, y = make_classification(n_samples=1000, n_features=20, random_state=42)

# Train a RandomForest model (replace with your actual model and training code)
model = RandomForestClassifier()
model.fit(X, y)

# Save the trained model to a file
joblib.dump(model, 'anomaly_detector.pkl')