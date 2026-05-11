"""
Unit tests for ProbabilityCalibrator

Tests cover:
- Initialization with valid and invalid methods
- Fitting with valid and invalid data
- Calibration of single probabilities
- Batch calibration
- Error handling and edge cases
"""

import numpy as np
import pytest

from backend.intelligence.calibration.probability_calibrator import ProbabilityCalibrator


class TestProbabilityCalibratorInit:
    """Tests for ProbabilityCalibrator initialization"""
    
    def test_init_platt_method(self):
        """Test initialization with Platt scaling method"""
        calibrator = ProbabilityCalibrator(method='platt')
        assert calibrator.method == 'platt'
        assert calibrator.calibrator is None
        assert calibrator.is_fitted is False
    
    def test_init_isotonic_method(self):
        """Test initialization with isotonic regression method"""
        calibrator = ProbabilityCalibrator(method='isotonic')
        assert calibrator.method == 'isotonic'
        assert calibrator.calibrator is None
        assert calibrator.is_fitted is False
    
    def test_init_default_method(self):
        """Test initialization with default method (platt)"""
        calibrator = ProbabilityCalibrator()
        assert calibrator.method == 'platt'
    
    def test_init_invalid_method(self):
        """Test initialization with invalid method raises ValueError"""
        with pytest.raises(ValueError, match="Invalid calibration method"):
            ProbabilityCalibrator(method='invalid')


class TestProbabilityCalibratorFit:
    """Tests for ProbabilityCalibrator.fit()"""
    
    def test_fit_platt_valid_data(self):
        """Test fitting Platt scaling with valid data"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        # Generate synthetic calibration data
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        
        assert calibrator.is_fitted is True
        assert calibrator.calibrator is not None
    
    def test_fit_isotonic_valid_data(self):
        """Test fitting isotonic regression with valid data"""
        calibrator = ProbabilityCalibrator(method='isotonic')
        
        # Generate synthetic calibration data
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        
        assert calibrator.is_fitted is True
        assert calibrator.calibrator is not None
    
    def test_fit_empty_data(self):
        """Test fitting with empty data raises ValueError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        with pytest.raises(ValueError, match="Cannot fit calibrator on empty dataset"):
            calibrator.fit(np.array([]), np.array([]))
    
    def test_fit_mismatched_lengths(self):
        """Test fitting with mismatched array lengths raises ValueError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        raw_probs = np.array([0.1, 0.2, 0.3])
        y_true = np.array([0, 1])
        
        with pytest.raises(ValueError, match="must have same length"):
            calibrator.fit(raw_probs, y_true)
    
    def test_fit_invalid_probability_range(self):
        """Test fitting with probabilities outside [0, 1] raises ValueError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        raw_probs = np.array([0.1, 0.5, 1.5])  # 1.5 is invalid
        y_true = np.array([0, 1, 1])
        
        with pytest.raises(ValueError, match="must be in range"):
            calibrator.fit(raw_probs, y_true)
    
    def test_fit_invalid_labels(self):
        """Test fitting with labels not in {0, 1} raises ValueError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        raw_probs = np.array([0.1, 0.5, 0.8])
        y_true = np.array([0, 1, 2])  # 2 is invalid
        
        with pytest.raises(ValueError, match="must contain only 0 and 1"):
            calibrator.fit(raw_probs, y_true)
    
    def test_fit_single_class(self):
        """Test fitting with only one class raises ValueError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        raw_probs = np.array([0.1, 0.2, 0.3])
        y_true = np.array([1, 1, 1])  # All positive
        
        with pytest.raises(ValueError, match="must contain both classes"):
            calibrator.fit(raw_probs, y_true)
    
    def test_fit_multidimensional_input(self):
        """Test fitting with multidimensional input raises ValueError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        raw_probs = np.array([[0.1, 0.2], [0.3, 0.4]])
        y_true = np.array([0, 1])
        
        with pytest.raises(ValueError, match="must be 1-dimensional"):
            calibrator.fit(raw_probs, y_true)
    
    def test_fit_small_dataset_warning(self, caplog):
        """Test fitting with small dataset logs warning"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        raw_probs = np.array([0.1, 0.9])
        y_true = np.array([0, 1])
        
        calibrator.fit(raw_probs, y_true)
        
        assert "very small" in caplog.text.lower()


class TestProbabilityCalibratorCalibrate:
    """Tests for ProbabilityCalibrator.calibrate()"""
    
    @pytest.fixture
    def fitted_platt_calibrator(self):
        """Fixture providing a fitted Platt calibrator"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        return calibrator
    
    @pytest.fixture
    def fitted_isotonic_calibrator(self):
        """Fixture providing a fitted isotonic calibrator"""
        calibrator = ProbabilityCalibrator(method='isotonic')
        
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        return calibrator
    
    def test_calibrate_platt_valid_probability(self, fitted_platt_calibrator):
        """Test calibrating a valid probability with Platt scaling"""
        calibrated = fitted_platt_calibrator.calibrate(0.7)
        
        assert isinstance(calibrated, float)
        assert 0 <= calibrated <= 1
    
    def test_calibrate_isotonic_valid_probability(self, fitted_isotonic_calibrator):
        """Test calibrating a valid probability with isotonic regression"""
        calibrated = fitted_isotonic_calibrator.calibrate(0.7)
        
        assert isinstance(calibrated, float)
        assert 0 <= calibrated <= 1
    
    def test_calibrate_boundary_values(self, fitted_platt_calibrator):
        """Test calibrating boundary values (0 and 1)"""
        calibrated_0 = fitted_platt_calibrator.calibrate(0.0)
        calibrated_1 = fitted_platt_calibrator.calibrate(1.0)
        
        assert 0 <= calibrated_0 <= 1
        assert 0 <= calibrated_1 <= 1
    
    def test_calibrate_unfitted_raises_error(self):
        """Test calibrating without fitting raises RuntimeError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        with pytest.raises(RuntimeError, match="has not been fitted"):
            calibrator.calibrate(0.5)
    
    def test_calibrate_invalid_probability_below_zero(self, fitted_platt_calibrator):
        """Test calibrating probability below 0 raises ValueError"""
        with pytest.raises(ValueError, match="must be in"):
            fitted_platt_calibrator.calibrate(-0.1)
    
    def test_calibrate_invalid_probability_above_one(self, fitted_platt_calibrator):
        """Test calibrating probability above 1 raises ValueError"""
        with pytest.raises(ValueError, match="must be in"):
            fitted_platt_calibrator.calibrate(1.5)
    
    def test_calibrate_invalid_type(self, fitted_platt_calibrator):
        """Test calibrating non-numeric value raises ValueError"""
        with pytest.raises(ValueError, match="must be a number"):
            fitted_platt_calibrator.calibrate("0.5")
    
    def test_calibrate_numpy_scalar(self, fitted_platt_calibrator):
        """Test calibrating numpy scalar works correctly"""
        calibrated = fitted_platt_calibrator.calibrate(np.float64(0.7))
        
        assert isinstance(calibrated, float)
        assert 0 <= calibrated <= 1
    
    def test_calibrate_multiple_values(self, fitted_platt_calibrator):
        """Test calibrating multiple individual values"""
        test_probs = [0.1, 0.3, 0.5, 0.7, 0.9]
        
        for prob in test_probs:
            calibrated = fitted_platt_calibrator.calibrate(prob)
            assert 0 <= calibrated <= 1


class TestProbabilityCalibratorCalibrateBatch:
    """Tests for ProbabilityCalibrator.calibrate_batch()"""
    
    @pytest.fixture
    def fitted_platt_calibrator(self):
        """Fixture providing a fitted Platt calibrator"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        return calibrator
    
    @pytest.fixture
    def fitted_isotonic_calibrator(self):
        """Fixture providing a fitted isotonic calibrator"""
        calibrator = ProbabilityCalibrator(method='isotonic')
        
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        return calibrator
    
    def test_calibrate_batch_platt(self, fitted_platt_calibrator):
        """Test batch calibration with Platt scaling"""
        raw_probs = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
        calibrated = fitted_platt_calibrator.calibrate_batch(raw_probs)
        
        assert isinstance(calibrated, np.ndarray)
        assert calibrated.shape == raw_probs.shape
        assert np.all((calibrated >= 0) & (calibrated <= 1))
    
    def test_calibrate_batch_isotonic(self, fitted_isotonic_calibrator):
        """Test batch calibration with isotonic regression"""
        raw_probs = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
        calibrated = fitted_isotonic_calibrator.calibrate_batch(raw_probs)
        
        assert isinstance(calibrated, np.ndarray)
        assert calibrated.shape == raw_probs.shape
        assert np.all((calibrated >= 0) & (calibrated <= 1))
    
    def test_calibrate_batch_empty_array(self, fitted_platt_calibrator):
        """Test batch calibration with empty array"""
        raw_probs = np.array([])
        calibrated = fitted_platt_calibrator.calibrate_batch(raw_probs)
        
        assert len(calibrated) == 0
    
    def test_calibrate_batch_single_value(self, fitted_platt_calibrator):
        """Test batch calibration with single value"""
        raw_probs = np.array([0.5])
        calibrated = fitted_platt_calibrator.calibrate_batch(raw_probs)
        
        assert len(calibrated) == 1
        assert 0 <= calibrated[0] <= 1
    
    def test_calibrate_batch_unfitted_raises_error(self):
        """Test batch calibration without fitting raises RuntimeError"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        with pytest.raises(RuntimeError, match="has not been fitted"):
            calibrator.calibrate_batch(np.array([0.5]))
    
    def test_calibrate_batch_invalid_range(self, fitted_platt_calibrator):
        """Test batch calibration with invalid probability range raises ValueError"""
        raw_probs = np.array([0.1, 0.5, 1.5])
        
        with pytest.raises(ValueError, match="must be in range"):
            fitted_platt_calibrator.calibrate_batch(raw_probs)
    
    def test_calibrate_batch_multidimensional(self, fitted_platt_calibrator):
        """Test batch calibration with multidimensional input raises ValueError"""
        raw_probs = np.array([[0.1, 0.2], [0.3, 0.4]])
        
        with pytest.raises(ValueError, match="must be 1-dimensional"):
            fitted_platt_calibrator.calibrate_batch(raw_probs)
    
    def test_calibrate_batch_consistency_with_single(self, fitted_platt_calibrator):
        """Test batch calibration produces same results as individual calibration"""
        raw_probs = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
        
        # Batch calibration
        batch_calibrated = fitted_platt_calibrator.calibrate_batch(raw_probs)
        
        # Individual calibration
        individual_calibrated = np.array([
            fitted_platt_calibrator.calibrate(p) for p in raw_probs
        ])
        
        # Should be very close (allowing for floating point precision)
        np.testing.assert_allclose(batch_calibrated, individual_calibrated, rtol=1e-10)


class TestProbabilityCalibratorEdgeCases:
    """Tests for edge cases and special scenarios"""
    
    def test_calibrate_with_perfectly_calibrated_data(self):
        """Test calibration when data is already perfectly calibrated"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        # Generate perfectly calibrated data
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 1000)
        y_true = (np.random.uniform(0, 1, 1000) < raw_probs).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        
        # Calibrated probabilities should be close to raw probabilities
        test_probs = np.array([0.1, 0.5, 0.9])
        calibrated = calibrator.calibrate_batch(test_probs)
        
        # Should be reasonably close (not exact due to sampling)
        assert np.allclose(calibrated, test_probs, atol=0.2)
    
    def test_calibrate_with_biased_data(self):
        """Test calibration with systematically biased probabilities"""
        calibrator = ProbabilityCalibrator(method='platt')
        
        # Generate biased data (model overconfident)
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        # True labels less likely than predicted
        y_true = (np.random.uniform(0, 1, 100) < raw_probs * 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        
        # High raw probability should be calibrated downward
        calibrated_high = calibrator.calibrate(0.9)
        assert calibrated_high < 0.9
    
    def test_isotonic_monotonicity(self):
        """Test that isotonic regression maintains monotonicity"""
        calibrator = ProbabilityCalibrator(method='isotonic')
        
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        calibrator.fit(raw_probs, y_true)
        
        # Test monotonicity: higher input should give higher output
        test_probs = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
        calibrated = calibrator.calibrate_batch(test_probs)
        
        # Check monotonicity
        for i in range(len(calibrated) - 1):
            assert calibrated[i] <= calibrated[i + 1], \
                f"Monotonicity violated: {calibrated[i]} > {calibrated[i + 1]}"
    
    def test_platt_vs_isotonic_comparison(self):
        """Test that both methods produce valid calibrations on same data"""
        np.random.seed(42)
        raw_probs = np.random.uniform(0, 1, 100)
        y_true = (raw_probs > 0.5).astype(int)
        
        # Fit both calibrators
        platt_calibrator = ProbabilityCalibrator(method='platt')
        platt_calibrator.fit(raw_probs, y_true)
        
        isotonic_calibrator = ProbabilityCalibrator(method='isotonic')
        isotonic_calibrator.fit(raw_probs, y_true)
        
        # Test on same probabilities
        test_probs = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
        
        platt_calibrated = platt_calibrator.calibrate_batch(test_probs)
        isotonic_calibrated = isotonic_calibrator.calibrate_batch(test_probs)
        
        # Both should produce valid probabilities
        assert np.all((platt_calibrated >= 0) & (platt_calibrated <= 1))
        assert np.all((isotonic_calibrated >= 0) & (isotonic_calibrated <= 1))
        
        # Results may differ but should be in similar range
        # (not testing exact equality as methods are different)
