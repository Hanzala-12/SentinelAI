"""
Probability Calibration Module

This module provides probability calibration for ML model outputs to ensure
that predicted probabilities reflect true empirical frequencies.

**Validates: Requirements 4.1-4.3**

Calibration Methods:
1. Platt Scaling: Fits logistic regression to transform raw probabilities
2. Isotonic Regression: Fits non-parametric monotonic function

Usage:
    calibrator = ProbabilityCalibrator(method='platt')
    calibrator.fit(raw_probs, y_true)
    calibrated_prob = calibrator.calibrate(raw_prob)
"""

import logging
from typing import Literal

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

logger = logging.getLogger(__name__)


class ProbabilityCalibrator:
    """
    Calibrates raw ML probabilities to match empirical frequencies.
    
    Supports two calibration methods:
    - Platt scaling (LogisticRegression): Parametric, works well with small calibration sets
    - Isotonic regression: Non-parametric, more flexible but requires larger calibration sets
    
    Attributes:
        method: Calibration method ('platt' or 'isotonic')
        calibrator: Fitted calibration model
        is_fitted: Whether the calibrator has been fitted
    """
    
    def __init__(self, method: Literal['platt', 'isotonic'] = 'platt'):
        """
        Initialize calibrator.
        
        Args:
            method: Calibration method to use
                - 'platt': Platt scaling using LogisticRegression
                - 'isotonic': Isotonic regression
                
        Raises:
            ValueError: If method is not 'platt' or 'isotonic'
        """
        if method not in ['platt', 'isotonic']:
            raise ValueError(f"Invalid calibration method: {method}. Must be 'platt' or 'isotonic'")
        
        self.method = method
        self.calibrator = None
        self.is_fitted = False
        
        logger.info(f"Initialized ProbabilityCalibrator with method={method}")
    
    def fit(self, raw_probs: np.ndarray, y_true: np.ndarray) -> None:
        """
        Fit calibrator on held-out calibration set.
        
        The calibrator learns the mapping from raw ML probabilities to calibrated
        probabilities that better reflect empirical frequencies.
        
        Args:
            raw_probs: Raw ML probabilities, shape (n_samples,), values in [0, 1]
            y_true: True labels, shape (n_samples,), values in {0, 1}
            
        Raises:
            ValueError: If inputs have invalid shapes or values
            RuntimeError: If calibration fitting fails
        """
        # Validate inputs
        raw_probs = np.asarray(raw_probs)
        y_true = np.asarray(y_true)
        
        if raw_probs.ndim != 1:
            raise ValueError(f"raw_probs must be 1-dimensional, got shape {raw_probs.shape}")
        
        if y_true.ndim != 1:
            raise ValueError(f"y_true must be 1-dimensional, got shape {y_true.shape}")
        
        if len(raw_probs) != len(y_true):
            raise ValueError(
                f"raw_probs and y_true must have same length, "
                f"got {len(raw_probs)} and {len(y_true)}"
            )
        
        if len(raw_probs) == 0:
            raise ValueError("Cannot fit calibrator on empty dataset")
        
        if not np.all((raw_probs >= 0) & (raw_probs <= 1)):
            raise ValueError("raw_probs must be in range [0, 1]")
        
        if not np.all((y_true == 0) | (y_true == 1)):
            raise ValueError("y_true must contain only 0 and 1")
        
        # Check for minimum samples
        if len(raw_probs) < 10:
            logger.warning(
                f"Calibration set is very small ({len(raw_probs)} samples). "
                "Calibration may be unreliable. Recommended minimum: 1000 samples."
            )
        
        # Check class balance
        n_positive = np.sum(y_true)
        n_negative = len(y_true) - n_positive
        if n_positive == 0 or n_negative == 0:
            raise ValueError(
                f"Calibration set must contain both classes. "
                f"Got {n_positive} positive and {n_negative} negative samples."
            )
        
        try:
            if self.method == 'platt':
                # Platt scaling: fit logistic regression on raw probabilities
                # P_calibrated = 1 / (1 + exp(A * P_raw + B))
                self.calibrator = LogisticRegression(random_state=42, max_iter=1000)
                # Reshape for sklearn: (n_samples, 1)
                self.calibrator.fit(raw_probs.reshape(-1, 1), y_true)
                
                logger.info(
                    f"Fitted Platt scaling calibrator on {len(raw_probs)} samples "
                    f"({n_positive} positive, {n_negative} negative)"
                )
                
            elif self.method == 'isotonic':
                # Isotonic regression: fit non-parametric monotonic function
                self.calibrator = IsotonicRegression(out_of_bounds='clip')
                self.calibrator.fit(raw_probs, y_true)
                
                logger.info(
                    f"Fitted isotonic regression calibrator on {len(raw_probs)} samples "
                    f"({n_positive} positive, {n_negative} negative)"
                )
            
            self.is_fitted = True
            
        except Exception as e:
            logger.error(f"Failed to fit calibrator: {e}")
            raise RuntimeError(f"Calibration fitting failed: {e}") from e
    
    def calibrate(self, raw_prob: float) -> float:
        """
        Calibrate a single probability.
        
        Transforms a raw ML probability into a calibrated probability that better
        reflects the true likelihood of the positive class.
        
        Args:
            raw_prob: Raw ML probability, value in [0, 1]
            
        Returns:
            Calibrated probability in [0, 1]
            
        Raises:
            ValueError: If raw_prob is not in [0, 1]
            RuntimeError: If calibrator has not been fitted
        """
        if not self.is_fitted:
            raise RuntimeError(
                "Calibrator has not been fitted. Call fit() before calibrate()."
            )
        
        # Validate input
        if not isinstance(raw_prob, (int, float, np.number)):
            raise ValueError(f"raw_prob must be a number, got {type(raw_prob)}")
        
        raw_prob = float(raw_prob)
        
        if not (0 <= raw_prob <= 1):
            raise ValueError(f"raw_prob must be in [0, 1], got {raw_prob}")
        
        try:
            if self.method == 'platt':
                # Use predict_proba to get calibrated probability
                calibrated_prob = self.calibrator.predict_proba(
                    np.array([[raw_prob]])
                )[0, 1]
                
            elif self.method == 'isotonic':
                # Isotonic regression directly predicts calibrated probability
                calibrated_prob = self.calibrator.predict([raw_prob])[0]
            
            # Ensure output is in [0, 1] (should be guaranteed by calibrators)
            calibrated_prob = np.clip(calibrated_prob, 0.0, 1.0)
            
            return float(calibrated_prob)
            
        except Exception as e:
            logger.error(f"Failed to calibrate probability {raw_prob}: {e}")
            # Fail-safe: return raw probability if calibration fails
            logger.warning(f"Returning uncalibrated probability due to error")
            return raw_prob
    
    def calibrate_batch(self, raw_probs: np.ndarray) -> np.ndarray:
        """
        Calibrate a batch of probabilities.
        
        More efficient than calling calibrate() in a loop for multiple probabilities.
        
        Args:
            raw_probs: Raw ML probabilities, shape (n_samples,), values in [0, 1]
            
        Returns:
            Calibrated probabilities, shape (n_samples,), values in [0, 1]
            
        Raises:
            ValueError: If raw_probs has invalid shape or values
            RuntimeError: If calibrator has not been fitted
        """
        if not self.is_fitted:
            raise RuntimeError(
                "Calibrator has not been fitted. Call fit() before calibrate_batch()."
            )
        
        # Validate inputs
        raw_probs = np.asarray(raw_probs)
        
        if raw_probs.ndim != 1:
            raise ValueError(f"raw_probs must be 1-dimensional, got shape {raw_probs.shape}")
        
        if not np.all((raw_probs >= 0) & (raw_probs <= 1)):
            raise ValueError("All raw_probs must be in range [0, 1]")
        
        try:
            if self.method == 'platt':
                calibrated_probs = self.calibrator.predict_proba(
                    raw_probs.reshape(-1, 1)
                )[:, 1]
                
            elif self.method == 'isotonic':
                calibrated_probs = self.calibrator.predict(raw_probs)
            
            # Ensure outputs are in [0, 1]
            calibrated_probs = np.clip(calibrated_probs, 0.0, 1.0)
            
            return calibrated_probs
            
        except Exception as e:
            logger.error(f"Failed to calibrate batch of {len(raw_probs)} probabilities: {e}")
            logger.warning(f"Returning uncalibrated probabilities due to error")
            return raw_probs
