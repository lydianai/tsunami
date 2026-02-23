#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI AI Model Trainer v5.0
    Machine Learning Model Training and Management
================================================================================
"""

import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class ModelType(Enum):
    """Supported model types"""
    ISOLATION_FOREST = "isolation_forest"
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"
    NEURAL_NETWORK = "neural_network"
    LSTM = "lstm"


@dataclass
class TrainingMetrics:
    """Model training metrics"""
    model_id: str
    model_type: ModelType
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    training_time: float = 0.0
    epochs: int = 0
    loss: float = 0.0
    validation_loss: float = 0.0
    training_samples: int = 0
    validation_samples: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelConfig:
    """Model configuration"""
    model_type: ModelType
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    feature_columns: List[str] = field(default_factory=list)
    target_column: str = ""
    validation_split: float = 0.2
    batch_size: int = 32
    max_epochs: int = 100
    early_stopping: bool = True
    early_stopping_patience: int = 10


class ModelManager:
    """
    Manages trained models - storage, versioning, deployment
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.models: Dict[str, Any] = {}
        self.active_models: Dict[str, str] = {}  # purpose -> model_id
        logger.info("ModelManager initialized")

    def register_model(
        self,
        model_id: str,
        model: Any,
        metrics: TrainingMetrics,
        purpose: str = "threat_detection"
    ) -> bool:
        """Register a trained model"""
        self.models[model_id] = {
            "model": model,
            "metrics": metrics,
            "purpose": purpose,
            "registered_at": datetime.now()
        }
        logger.info(f"Registered model: {model_id} for {purpose}")
        return True

    def get_model(self, model_id: str) -> Optional[Any]:
        """Get model by ID"""
        if model_id in self.models:
            return self.models[model_id]["model"]
        return None

    def get_active_model(self, purpose: str) -> Optional[Any]:
        """Get active model for a purpose"""
        model_id = self.active_models.get(purpose)
        if model_id:
            return self.get_model(model_id)
        return None

    def activate_model(self, model_id: str, purpose: str) -> bool:
        """Activate a model for production use"""
        if model_id in self.models:
            self.active_models[purpose] = model_id
            logger.info(f"Activated model {model_id} for {purpose}")
            return True
        return False

    def list_models(self, purpose: Optional[str] = None) -> List[Dict[str, Any]]:
        """List registered models"""
        result = []
        for model_id, data in self.models.items():
            if purpose is None or data["purpose"] == purpose:
                result.append({
                    "model_id": model_id,
                    "purpose": data["purpose"],
                    "metrics": data["metrics"],
                    "registered_at": data["registered_at"]
                })
        return result

    def get_status(self) -> Dict[str, Any]:
        """Get manager status"""
        return {
            "total_models": len(self.models),
            "active_models": self.active_models.copy(),
            "models_by_purpose": {}
        }


class ModelTrainer:
    """
    Handles model training for threat detection
    """

    def __init__(self, manager: Optional[ModelManager] = None):
        self.manager = manager or ModelManager()
        self.training_history: List[TrainingMetrics] = []
        logger.info("ModelTrainer initialized")

    def train(
        self,
        config: ModelConfig,
        training_data: Any,
        validation_data: Optional[Any] = None
    ) -> TrainingMetrics:
        """
        Train a model with given configuration and data using scikit-learn.
        Supports IsolationForest, RandomForest, GradientBoosting, and basic NN.
        """
        import time as _time
        t0 = _time.time()
        model_id = f"{config.model_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        model = None
        accuracy = 0.0
        precision_val = 0.0
        recall_val = 0.0
        f1 = 0.0
        n_train = 0
        n_val = 0

        try:
            import numpy as np

            # Convert training data to numpy arrays
            if hasattr(training_data, 'values') and hasattr(training_data, 'columns'):
                # Pandas DataFrame
                X = training_data.drop(columns=[config.target_column], errors='ignore').values
                y = training_data[config.target_column].values if config.target_column in training_data.columns else None
            elif isinstance(training_data, dict):
                X = np.array(training_data.get('X', training_data.get('features', [])))
                y = np.array(training_data.get('y', training_data.get('labels', []))) if 'y' in training_data or 'labels' in training_data else None
            elif isinstance(training_data, (list, tuple)) and len(training_data) == 2:
                X = np.array(training_data[0])
                y = np.array(training_data[1]) if training_data[1] is not None else None
            else:
                X = np.array(training_data)
                y = None

            n_train = len(X)

            # Validation split
            if validation_data is not None:
                if isinstance(validation_data, dict):
                    X_val = np.array(validation_data.get('X', validation_data.get('features', [])))
                    y_val = np.array(validation_data.get('y', validation_data.get('labels', []))) if 'y' in validation_data else None
                else:
                    X_val, y_val = np.array(validation_data[0]), np.array(validation_data[1]) if len(validation_data) == 2 else (np.array(validation_data), None)
            elif y is not None and hasattr(y, 'ndim') and y.ndim > 0 and len(y) > 0 and config.validation_split > 0:
                split_idx = int(len(X) * (1 - config.validation_split))
                X_val, y_val = X[split_idx:], y[split_idx:]
                X, y = X[:split_idx], y[:split_idx]
                n_train = len(X)
            else:
                X_val, y_val = None, None

            n_val = len(X_val) if X_val is not None else 0

            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score as sk_f1

            if config.model_type == ModelType.ISOLATION_FOREST:
                from sklearn.ensemble import IsolationForest
                hp = config.hyperparameters
                model = IsolationForest(
                    n_estimators=hp.get('n_estimators', 100),
                    contamination=hp.get('contamination', 0.1),
                    random_state=42
                )
                model.fit(X)
                preds = model.predict(X)
                # IsolationForest: -1=anomaly, 1=normal → convert
                if y is not None:
                    accuracy = accuracy_score(y, (preds == -1).astype(int))
                else:
                    anomaly_ratio = (preds == -1).sum() / len(preds)
                    accuracy = 1.0 - abs(anomaly_ratio - 0.1)  # How close to expected contamination

            elif config.model_type == ModelType.RANDOM_FOREST:
                from sklearn.ensemble import RandomForestClassifier
                hp = config.hyperparameters
                model = RandomForestClassifier(
                    n_estimators=hp.get('n_estimators', 100),
                    max_depth=hp.get('max_depth', None),
                    random_state=42
                )
                model.fit(X, y)
                if X_val is not None and y_val is not None:
                    preds = model.predict(X_val)
                    accuracy = accuracy_score(y_val, preds)
                    precision_val = precision_score(y_val, preds, average='weighted', zero_division=0)
                    recall_val = recall_score(y_val, preds, average='weighted', zero_division=0)
                    f1 = sk_f1(y_val, preds, average='weighted', zero_division=0)
                else:
                    preds = model.predict(X)
                    accuracy = accuracy_score(y, preds)

            elif config.model_type == ModelType.GRADIENT_BOOSTING:
                from sklearn.ensemble import GradientBoostingClassifier
                hp = config.hyperparameters
                model = GradientBoostingClassifier(
                    n_estimators=hp.get('n_estimators', 100),
                    learning_rate=hp.get('learning_rate', 0.1),
                    max_depth=hp.get('max_depth', 3),
                    random_state=42
                )
                model.fit(X, y)
                if X_val is not None and y_val is not None:
                    preds = model.predict(X_val)
                    accuracy = accuracy_score(y_val, preds)
                    precision_val = precision_score(y_val, preds, average='weighted', zero_division=0)
                    recall_val = recall_score(y_val, preds, average='weighted', zero_division=0)
                    f1 = sk_f1(y_val, preds, average='weighted', zero_division=0)
                else:
                    preds = model.predict(X)
                    accuracy = accuracy_score(y, preds)

            elif config.model_type in (ModelType.NEURAL_NETWORK, ModelType.LSTM):
                from sklearn.neural_network import MLPClassifier
                hp = config.hyperparameters
                hidden = hp.get('hidden_layer_sizes', (100, 50))
                if isinstance(hidden, list):
                    hidden = tuple(hidden)
                model = MLPClassifier(
                    hidden_layer_sizes=hidden,
                    max_iter=config.max_epochs,
                    early_stopping=config.early_stopping,
                    random_state=42
                )
                model.fit(X, y)
                if X_val is not None and y_val is not None:
                    preds = model.predict(X_val)
                    accuracy = accuracy_score(y_val, preds)
                    precision_val = precision_score(y_val, preds, average='weighted', zero_division=0)
                    recall_val = recall_score(y_val, preds, average='weighted', zero_division=0)
                    f1 = sk_f1(y_val, preds, average='weighted', zero_division=0)
                else:
                    preds = model.predict(X)
                    accuracy = accuracy_score(y, preds)

        except ImportError as e:
            logger.error(f"scikit-learn kurulu degil: {e}")
            raise RuntimeError(f"Egitim icin scikit-learn gerekli: pip install scikit-learn. Hata: {e}")
        except Exception as e:
            logger.error(f"Model egitim hatasi: {e}")
            raise

        training_time = _time.time() - t0

        metrics = TrainingMetrics(
            model_id=model_id,
            model_type=config.model_type,
            accuracy=round(accuracy, 4),
            precision=round(precision_val, 4),
            recall=round(recall_val, 4),
            f1_score=round(f1, 4),
            training_time=round(training_time, 3),
            epochs=config.max_epochs,
            training_samples=n_train,
            validation_samples=n_val
        )

        self.manager.register_model(model_id, model, metrics)
        self.training_history.append(metrics)

        logger.info(f"Trained model: {model_id} - accuracy={accuracy:.4f}")
        return metrics

    def evaluate(self, model_id: str, test_data: Any) -> Dict[str, float]:
        """Evaluate a trained model on test data"""
        model = self.manager.get_model(model_id)
        if model is None:
            return {"error": f"Model {model_id} bulunamadi"}

        try:
            import numpy as np
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score as sk_f1

            if isinstance(test_data, dict):
                X_test = np.array(test_data.get('X', test_data.get('features', [])))
                y_test = np.array(test_data.get('y', test_data.get('labels', [])))
            elif isinstance(test_data, (list, tuple)) and len(test_data) == 2:
                X_test, y_test = np.array(test_data[0]), np.array(test_data[1])
            else:
                return {"error": "Test verisi {X, y} veya (X, y) formatinda olmali"}

            preds = model.predict(X_test)

            # Handle IsolationForest output
            if hasattr(model, 'contamination'):
                preds = (preds == -1).astype(int)

            return {
                "accuracy": round(float(accuracy_score(y_test, preds)), 4),
                "precision": round(float(precision_score(y_test, preds, average='weighted', zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, preds, average='weighted', zero_division=0)), 4),
                "f1_score": round(float(sk_f1(y_test, preds, average='weighted', zero_division=0)), 4)
            }
        except ImportError:
            return {"error": "scikit-learn kurulu degil"}
        except Exception as e:
            return {"error": str(e)}

    def get_training_history(self) -> List[TrainingMetrics]:
        """Get training history"""
        return self.training_history.copy()

    def get_status(self) -> Dict[str, Any]:
        """Get trainer status"""
        return {
            "models_trained": len(self.training_history),
            "manager_status": self.manager.get_status()
        }


# Global instances
_model_manager: Optional[ModelManager] = None
_model_trainer: Optional[ModelTrainer] = None


def get_model_manager() -> ModelManager:
    """Get the global ModelManager instance"""
    global _model_manager
    if _model_manager is None:
        _model_manager = ModelManager()
    return _model_manager


def get_model_trainer() -> ModelTrainer:
    """Get the global ModelTrainer instance"""
    global _model_trainer
    if _model_trainer is None:
        _model_trainer = ModelTrainer(get_model_manager())
    return _model_trainer
