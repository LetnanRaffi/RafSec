"""
RafSec Engine - Machine Learning Threat Classifier
====================================================
ML-based malware detection using RandomForest.

Author: RafSec Team

WHY MACHINE LEARNING FOR MALWARE:
- Traditional signatures can't detect new/modified malware
- ML learns PATTERNS from thousands of samples
- Can generalize to detect never-before-seen threats
- Combines multiple weak indicators into strong prediction
"""

import os
import numpy as np
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
import pickle
import warnings
from pathlib import Path

# Suppress sklearn warnings for cleaner output
warnings.filterwarnings('ignore')

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[WARNING] scikit-learn not installed. ML features disabled.")


@dataclass
class MLPrediction:
    """Machine learning prediction result."""
    is_malicious: bool
    confidence: float  # 0.0 to 1.0
    probabilities: Dict[str, float]  # {'benign': 0.3, 'malicious': 0.7}
    features_used: int
    model_version: str


class FeatureVectorizer:
    """
    Converts PEFeatures into numerical vectors for ML.
    
    WHY FEATURE ENGINEERING MATTERS:
    - ML models only understand numbers
    - Raw PE data must be converted to meaningful metrics
    - Good features = good predictions
    """
    
    # Feature names for reference
    FEATURE_NAMES = [
        'file_size',
        'overall_entropy',
        'num_sections',
        'num_imports',
        'num_suspicious_imports',
        'has_import_table',
        'entry_point_anomaly',
        'e_lfanew_anomaly',
        'max_section_entropy',
        'num_write_execute_sections',
        'num_high_entropy_sections',
        'has_resources',
        'imphash_exists',
        'suspicious_section_names',
        'timestamp_anomaly',
    ]
    
    @classmethod
    def vectorize(cls, features) -> np.ndarray:
        """
        Convert PEFeatures into a numerical feature vector.
        
        Args:
            features: PEFeatures object
            
        Returns:
            numpy array of shape (15,)
        """
        # Calculate derived features
        max_entropy = max(
            (s.entropy for s in features.sections), 
            default=0.0
        )
        
        wx_sections = sum(
            1 for s in features.sections 
            if s.is_writable and s.is_executable
        )
        
        high_entropy_sections = sum(
            1 for s in features.sections 
            if s.entropy > 7.0
        )
        
        suspicious_names = sum(
            1 for s in features.sections
            if s.name.lower() in ['.upx', '.vmp', '.packed', '.themida']
        )
        
        timestamp_anomaly = any(
            'timestamp' in a.lower() 
            for a in features.anomalies
        )
        
        # Build feature vector
        vector = [
            features.file_size / 1_000_000,  # Normalize to MB
            features.overall_entropy,
            features.number_of_sections,
            features.total_imports,
            len(features.suspicious_imports),
            float(features.has_imports),
            float(features.entry_point_anomaly),
            float(features.e_lfanew_anomaly),
            max_entropy,
            wx_sections,
            high_entropy_sections,
            float(features.has_resources),
            float(features.imphash != 'N/A' and features.imphash != ''),
            suspicious_names,
            float(timestamp_anomaly),
        ]
        
        return np.array(vector, dtype=np.float32)
    
    @classmethod
    def get_feature_names(cls) -> List[str]:
        """Return list of feature names for interpretation."""
        return cls.FEATURE_NAMES.copy()


# Placeholder class when sklearn is not available
class _ThreatClassifierPlaceholder:
    """Placeholder when sklearn is not available."""
    
    MODEL_VERSION = "1.0.0"
    
    def __init__(self, *args, **kwargs):
        print("[WARNING] ML features disabled - sklearn not available")
    
    def predict(self, features) -> MLPrediction:
        """Return a neutral prediction when ML is unavailable."""
        return MLPrediction(
            is_malicious=False,
            confidence=0.5,
            probabilities={'benign': 0.5, 'malicious': 0.5},
            features_used=0,
            model_version=self.MODEL_VERSION + "-placeholder"
        )
    
    def train_with_dummy_data(self):
        return {'accuracy': 0, 'error': 'sklearn not available'}
    
    def save_model(self, *args, **kwargs):
        pass
    
    def load_model(self, *args, **kwargs):
        return False


if SKLEARN_AVAILABLE:
    class ThreatClassifier:
        """
        RandomForest-based malware classifier.
        
        Architecture:
        - Uses RandomForest: ensemble of decision trees
        - Each tree votes on benign/malicious
        - Final prediction is majority vote
        - Confidence = percentage of trees agreeing
        
        WHY RANDOMFOREST:
        - Works well with small datasets
        - Handles mixed feature types (numeric + boolean)
        - Provides feature importance (explainability)
        - Resistant to overfitting
        """
        
        MODEL_VERSION = "1.0.0"
        MODEL_FILENAME = "threat_model.pkl"
        
        def __init__(self, model_path: Optional[str] = None):
            """
            Initialize classifier.
            
            Args:
                model_path: Path to saved model file. If None, uses default.
            """
            self.model: Optional[RandomForestClassifier] = None
            self.model_path = model_path or self._default_model_path()
            self.is_trained = False
            
            # Try to load existing model
            if os.path.exists(self.model_path):
                self.load_model()
        
        def _default_model_path(self) -> str:
            """Get default model save path."""
            return os.path.join(
                os.path.dirname(__file__), 
                'models',
                self.MODEL_FILENAME
            )
        
        def _create_model(self) -> RandomForestClassifier:
            """
            Create a new RandomForest model with optimal parameters.
            
            Parameters explained:
            - n_estimators=100: Use 100 decision trees (more = better but slower)
            - max_depth=10: Limit tree depth to prevent overfitting
            - min_samples_split=5: Require 5 samples to create a split
            - class_weight='balanced': Handle imbalanced datasets
            - random_state=42: Reproducible results
            """
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1  # Use all CPU cores
            )
        
        def train(self, 
                  X: np.ndarray, 
                  y: np.ndarray,
                  test_size: float = 0.2) -> Dict[str, Any]:
            """
            Train the classifier on labeled data.
            
            Args:
                X: Feature vectors, shape (n_samples, 15)
                y: Labels, 0=benign, 1=malicious
                test_size: Fraction for test split
                
            Returns:
                Training metrics dictionary
            """
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            # Train model
            self.model = self._create_model()
            self.model.fit(X_train, y_train)
            self.is_trained = True
            
            # Evaluate
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Feature importance
            importances = dict(zip(
                FeatureVectorizer.FEATURE_NAMES,
                self.model.feature_importances_
            ))
            
            return {
                'accuracy': accuracy,
                'samples_trained': len(X_train),
                'samples_tested': len(X_test),
                'feature_importance': importances,
                'classification_report': classification_report(
                    y_test, y_pred, 
                    target_names=['Benign', 'Malicious']
                )
            }
        
        def train_with_dummy_data(self) -> Dict[str, Any]:
            """
            Train model with synthetic dummy data for demonstration.
            
            In production, replace this with real malware samples!
            
            Creates synthetic data that mimics real malware characteristics:
            - Benign: lower entropy, more imports, standard structure
            - Malicious: higher entropy, fewer imports, anomalies
            """
            np.random.seed(42)
            n_samples = 500
            
            # Generate BENIGN samples
            benign_samples = np.column_stack([
                np.random.uniform(0.01, 5, n_samples),      # file_size (MB)
                np.random.uniform(4.0, 6.5, n_samples),     # overall_entropy
                np.random.randint(3, 8, n_samples),         # num_sections
                np.random.randint(20, 200, n_samples),      # num_imports
                np.random.randint(0, 3, n_samples),         # suspicious_imports
                np.ones(n_samples),                          # has_import_table
                np.zeros(n_samples),                         # entry_point_anomaly
                np.zeros(n_samples),                         # e_lfanew_anomaly
                np.random.uniform(5.0, 6.5, n_samples),     # max_section_entropy
                np.zeros(n_samples),                         # wx_sections
                np.zeros(n_samples),                         # high_entropy_sections
                np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),  # has_resources
                np.ones(n_samples),                          # imphash_exists
                np.zeros(n_samples),                         # suspicious_section_names
                np.zeros(n_samples),                         # timestamp_anomaly
            ])
            
            # Generate MALICIOUS samples
            malicious_samples = np.column_stack([
                np.random.uniform(0.05, 2, n_samples),      # file_size (usually smaller)
                np.random.uniform(6.5, 7.9, n_samples),     # higher entropy
                np.random.randint(2, 6, n_samples),         # fewer sections
                np.random.randint(0, 30, n_samples),        # fewer imports
                np.random.randint(2, 15, n_samples),        # more suspicious
                np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),  # may lack imports
                np.random.choice([0, 1], n_samples, p=[0.4, 0.6]),  # EP anomaly
                np.random.choice([0, 1], n_samples, p=[0.7, 0.3]),  # e_lfanew issue
                np.random.uniform(6.5, 7.9, n_samples),     # high section entropy
                np.random.randint(0, 3, n_samples),         # WX sections
                np.random.randint(0, 4, n_samples),         # high entropy sections
                np.random.choice([0, 1], n_samples, p=[0.6, 0.4]),  # resources
                np.random.choice([0, 1], n_samples, p=[0.4, 0.6]),  # imphash
                np.random.randint(0, 3, n_samples),         # suspicious names
                np.random.choice([0, 1], n_samples, p=[0.5, 0.5]),  # timestamp
            ])
            
            # Combine and create labels
            X = np.vstack([benign_samples, malicious_samples]).astype(np.float32)
            y = np.array([0] * n_samples + [1] * n_samples)
            
            # Shuffle
            shuffle_idx = np.random.permutation(len(X))
            X, y = X[shuffle_idx], y[shuffle_idx]
            
            return self.train(X, y)
        
        def predict(self, features) -> MLPrediction:
            """
            Predict if a file is malicious.
            
            Args:
                features: PEFeatures object
                
            Returns:
                MLPrediction with result and confidence
            """
            if not self.is_trained:
                # Auto-train with dummy data if no model exists
                print("[INFO] No trained model found. Training with dummy data...")
                self.train_with_dummy_data()
                self.save_model()
            
            # Vectorize features
            X = FeatureVectorizer.vectorize(features).reshape(1, -1)
            
            # Get prediction and probabilities
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            return MLPrediction(
                is_malicious=bool(prediction == 1),
                confidence=float(max(probabilities)),
                probabilities={
                    'benign': float(probabilities[0]),
                    'malicious': float(probabilities[1])
                },
                features_used=X.shape[1],
                model_version=self.MODEL_VERSION
            )
        
        def get_feature_importance(self) -> Dict[str, float]:
            """
            Get feature importance scores.
            
            WHY THIS MATTERS:
            - Tells us which features best distinguish malware
            - Helps improve feature engineering
            - Provides explainability for predictions
            """
            if not self.is_trained:
                return {}
            
            return dict(zip(
                FeatureVectorizer.FEATURE_NAMES,
                self.model.feature_importances_
            ))
        
        def save_model(self, path: Optional[str] = None) -> None:
            """Save trained model to disk."""
            save_path = path or self.model_path
            
            # Create directory if needed
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            model_data = {
                'model': self.model,
                'version': self.MODEL_VERSION,
                'feature_names': FeatureVectorizer.FEATURE_NAMES
            }
            
            joblib.dump(model_data, save_path)
            print(f"[INFO] Model saved to: {save_path}")
        
        def load_model(self, path: Optional[str] = None) -> bool:
            """Load trained model from disk."""
            load_path = path or self.model_path
            
            try:
                model_data = joblib.load(load_path)
                self.model = model_data['model']
                self.is_trained = True
                print(f"[INFO] Model loaded from: {load_path}")
                return True
            except Exception as e:
                print(f"[WARNING] Could not load model: {e}")
                return False

    class EnsembleClassifier:
        """
        Combine multiple models for better accuracy.
        
        WHY ENSEMBLE:
        - Different models catch different patterns
        - Voting reduces false positives/negatives
        - More robust against adversarial samples
        """
        
        def __init__(self):
            """Initialize ensemble components."""
            self.random_forest = ThreatClassifier()
            # Add more classifiers here in production:
            # self.gradient_boost = GradientBoostClassifier()
            # self.neural_net = NeuralNetClassifier()
        
        def predict(self, features) -> Dict[str, Any]:
            """
            Get ensemble prediction.
            
            Currently uses single model, but structured for expansion.
            """
            rf_result = self.random_forest.predict(features)
            
            # In production, average predictions from multiple models
            return {
                'final_verdict': 'MALICIOUS' if rf_result.is_malicious else 'BENIGN',
                'confidence': rf_result.confidence,
                'models': {
                    'random_forest': rf_result.probabilities
                }
            }
else:
    # Use placeholder when sklearn is not available
    ThreatClassifier = _ThreatClassifierPlaceholder
    
    class EnsembleClassifier:
        """Placeholder ensemble when sklearn unavailable."""
        def __init__(self):
            self.random_forest = ThreatClassifier()
        
        def predict(self, features) -> Dict[str, Any]:
            rf_result = self.random_forest.predict(features)
            return {
                'final_verdict': 'UNKNOWN',
                'confidence': 0.5,
                'models': {'random_forest': rf_result.probabilities}
            }
