"""
Autoencoder for Process Behavior Anomaly Detection

Uses Keras/TensorFlow to train an autoencoder on syscall patterns.
Anomalies are detected when reconstruction error exceeds threshold.
"""

import logging
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from tensorflow import keras

from lib import MAX_SYSCALLS

logger = logging.getLogger(__name__)


def create_autoencoder(n_inputs: int = MAX_SYSCALLS) -> keras.Model:
    """
    Create the autoencoder architecture.

    Architecture: input → encoder → bottleneck → decoder → output
    """
    inp = keras.Input(shape=(n_inputs,))

    # Encoder
    encoder = keras.layers.Dense(n_inputs)(inp)
    encoder = keras.layers.ReLU()(encoder)

    # Bottleneck (compressed representation)
    bottleneck = keras.layers.Dense(n_inputs // 2)(encoder)

    # Decoder
    decoder = keras.layers.Dense(n_inputs)(bottleneck)
    decoder = keras.layers.ReLU()(decoder)
    output = keras.layers.Dense(n_inputs, activation="linear")(decoder)

    model = keras.Model(inp, output)
    model.compile(optimizer="adam", loss="mse")

    return model


class AutoEncoder:
    """
    Autoencoder for syscall pattern anomaly detection.

    Usage:
        # Training
        ae = AutoEncoder('model.keras')
        model, threshold = ae.train('data.csv', epochs=200)

        # Inference
        ae = AutoEncoder('model.keras', load=True)
        _, errors, total_error = ae.predict([features])
    """

    def __init__(self, filename: str, load: bool = False):
        self.filename = filename
        self.model = None

        if load:
            self._load_model()

    def _load_model(self) -> None:
        """Load a trained model from disk."""
        if not os.path.exists(self.filename):
            raise FileNotFoundError(f"Model file not found: {self.filename}")

        logger.info(f"Loading model from {self.filename}")
        self.model = keras.models.load_model(self.filename)

    def train(
        self,
        datafile: str,
        epochs: int,
        batch_size: int,
        test_size: float = 0.1,
    ) -> tuple[keras.Model, float]:
        """
        Train the autoencoder on collected data.

        Args:
            datafile: Path to CSV file with training data
            epochs: Number of training epochs
            batch_size: Training batch size
            test_size: Fraction of data to use for validation

        Returns:
            Tuple of (trained model, error threshold)
        """
        if not os.path.exists(datafile):
            raise FileNotFoundError(f"Data file not found: {datafile}")

        logger.info(f"Loading training data from {datafile}")

        # Load and prepare data
        df = pd.read_csv(datafile)
        features = df.drop(["sample_time"], axis=1).values

        logger.info(f"Loaded {len(features)} samples with {features.shape[1]} features")

        # Split train/test
        train_data, test_data = train_test_split(
            features,
            test_size=test_size,
            random_state=42,
        )

        logger.info(f"Training set: {len(train_data)} samples")
        logger.info(f"Test set: {len(test_data)} samples")

        # Create and train model
        self.model = create_autoencoder()

        if self.model is None:
            raise RuntimeError("Failed to create the autoencoder model.")

        logger.info("Training autoencoder...")
        self.model.fit(
            train_data,
            train_data,
            validation_data=(test_data, test_data),
            epochs=epochs,
            batch_size=batch_size,
            verbose=1,
        )

        # Save model (use .keras format for Keras 3.x compatibility)
        self.model.save(self.filename)
        logger.info(f"Model saved to {self.filename}")

        # Calculate error threshold from test data
        threshold = self._calculate_threshold(test_data)

        return self.model, threshold

    def _calculate_threshold(self, test_data: np.ndarray) -> float:
        """Calculate error threshold from test data."""
        logger.info(f"Calculating error threshold from {len(test_data)} test samples")

        if self.model is None:
            raise RuntimeError("Model not loaded. Use load=True or train first.")

        predictions = self.model.predict(test_data, verbose=0)
        errors = np.abs(test_data - predictions).sum(axis=1)

        return float(errors.max())

    def predict(self, X: list | np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
        """
        Run prediction and return reconstruction error.

        Args:
            X: Input data (list of feature vectors)

        Returns:
            Tuple of (reconstructed, per_feature_errors, total_error)
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Use load=True or train first.")

        X = np.asarray(X, dtype=np.float32)
        y = self.model.predict(X, verbose=0)

        # Per-feature reconstruction error
        errors = np.abs(X[0] - y[0])
        total_error = float(errors.sum())

        return y, errors, total_error
