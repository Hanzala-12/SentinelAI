"""
Integration test for ProbabilityCalibrator

Demonstrates end-to-end usage of the calibrator with realistic scenarios.
"""

import numpy as np
import pytest

from backend.intelligence.calibration.probability_calibrator import ProbabilityCalibrator


def test_calibrator_end_to_end_workflow():
    """
    Test complete workflow: fit calibrator on training data, 
    then calibrate test probabilities.
    """
    # Simulate a scenario where ML model is overconfident
    np.random.seed(42)
    
    # Generate calibration set (held-out from training)
    n_calibration = 1000
    raw_probs_cal = np.random.beta(2, 2, n_calibration)  # Probabilities centered around 0.5
    
    # Simulate overconfident model: true labels less likely than predicted
    y_true_cal = (np.random.uniform(0, 1, n_calibration) < raw_probs_cal * 0.7).astype(int)
    
    # Fit calibrator
    calibrator = ProbabilityCalibrator(method='platt')
    calibrator.fit(raw_probs_cal, y_true_cal)
    
    # Test on new data
    test_probs = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    calibrated_probs = calibrator.calibrate_batch(test_probs)
    
    # Verify calibration reduces overconfidence
    # High probabilities should be calibrated downward
    assert calibrated_probs[-1] < test_probs[-1], "High probability should be calibrated down"
    
    # All outputs should be valid probabilities
    assert np.all((calibrated_probs >= 0) & (calibrated_probs <= 1))
    
    print(f"Raw probabilities:        {test_probs}")
    print(f"Calibrated probabilities: {calibrated_probs}")


def test_calibrator_with_realistic_imbalanced_data():
    """
    Test calibrator with realistic imbalanced dataset (99/1 benign/phishing).
    """
    np.random.seed(42)
    
    # Generate imbalanced calibration set
    n_benign = 990
    n_phishing = 10
    
    # Benign URLs: low probabilities
    benign_probs = np.random.beta(1, 5, n_benign)  # Skewed toward 0
    benign_labels = np.zeros(n_benign, dtype=int)
    
    # Phishing URLs: high probabilities
    phishing_probs = np.random.beta(5, 1, n_phishing)  # Skewed toward 1
    phishing_labels = np.ones(n_phishing, dtype=int)
    
    # Combine
    raw_probs = np.concatenate([benign_probs, phishing_probs])
    y_true = np.concatenate([benign_labels, phishing_labels])
    
    # Shuffle
    indices = np.random.permutation(len(raw_probs))
    raw_probs = raw_probs[indices]
    y_true = y_true[indices]
    
    # Fit calibrator
    calibrator = ProbabilityCalibrator(method='isotonic')
    calibrator.fit(raw_probs, y_true)
    
    # Test calibration
    test_prob_low = 0.1  # Should stay low
    test_prob_high = 0.9  # Should stay high
    
    calibrated_low = calibrator.calibrate(test_prob_low)
    calibrated_high = calibrator.calibrate(test_prob_high)
    
    assert calibrated_low < 0.5, "Low probability should remain low"
    assert calibrated_high > 0.5, "High probability should remain high"
    
    print(f"Low probability: {test_prob_low} -> {calibrated_low}")
    print(f"High probability: {test_prob_high} -> {calibrated_high}")


def test_calibrator_comparison_platt_vs_isotonic():
    """
    Compare Platt scaling and isotonic regression on same dataset.
    """
    np.random.seed(42)
    
    # Generate calibration data
    n_samples = 500
    raw_probs = np.random.uniform(0, 1, n_samples)
    y_true = (raw_probs > 0.5).astype(int)
    
    # Fit both calibrators
    platt_calibrator = ProbabilityCalibrator(method='platt')
    platt_calibrator.fit(raw_probs, y_true)
    
    isotonic_calibrator = ProbabilityCalibrator(method='isotonic')
    isotonic_calibrator.fit(raw_probs, y_true)
    
    # Test on same probabilities
    test_probs = np.linspace(0, 1, 11)
    
    platt_calibrated = platt_calibrator.calibrate_batch(test_probs)
    isotonic_calibrated = isotonic_calibrator.calibrate_batch(test_probs)
    
    print("\nCalibration comparison:")
    print("Raw       | Platt     | Isotonic")
    print("-" * 35)
    for raw, platt, iso in zip(test_probs, platt_calibrated, isotonic_calibrated):
        print(f"{raw:.2f}      | {platt:.4f}    | {iso:.4f}")
    
    # Both should produce valid probabilities
    assert np.all((platt_calibrated >= 0) & (platt_calibrated <= 1))
    assert np.all((isotonic_calibrated >= 0) & (isotonic_calibrated <= 1))


def test_calibrator_expected_calibration_error():
    """
    Test that calibration reduces Expected Calibration Error (ECE).
    """
    np.random.seed(42)
    
    # Generate poorly calibrated data
    n_samples = 1000
    raw_probs = np.random.uniform(0, 1, n_samples)
    # Model is systematically overconfident
    y_true = (np.random.uniform(0, 1, n_samples) < raw_probs * 0.6).astype(int)
    
    # Split into calibration and test sets
    split_idx = 500
    raw_probs_cal = raw_probs[:split_idx]
    y_true_cal = y_true[:split_idx]
    raw_probs_test = raw_probs[split_idx:]
    y_true_test = y_true[split_idx:]
    
    # Fit calibrator
    calibrator = ProbabilityCalibrator(method='platt')
    calibrator.fit(raw_probs_cal, y_true_cal)
    
    # Calibrate test probabilities
    calibrated_probs_test = calibrator.calibrate_batch(raw_probs_test)
    
    # Compute ECE for raw and calibrated probabilities
    def compute_ece(probs, labels, n_bins=10):
        """Compute Expected Calibration Error"""
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        
        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]
            
            in_bin = (probs >= bin_lower) & (probs < bin_upper)
            if i == n_bins - 1:  # Include 1.0 in last bin
                in_bin = (probs >= bin_lower) & (probs <= bin_upper)
            
            if np.sum(in_bin) > 0:
                bin_accuracy = np.mean(labels[in_bin])
                bin_confidence = np.mean(probs[in_bin])
                bin_weight = np.sum(in_bin) / len(probs)
                
                ece += bin_weight * np.abs(bin_accuracy - bin_confidence)
        
        return ece
    
    ece_raw = compute_ece(raw_probs_test, y_true_test)
    ece_calibrated = compute_ece(calibrated_probs_test, y_true_test)
    
    print(f"\nExpected Calibration Error:")
    print(f"Raw probabilities:        {ece_raw:.4f}")
    print(f"Calibrated probabilities: {ece_calibrated:.4f}")
    print(f"Improvement:              {(ece_raw - ece_calibrated):.4f}")
    
    # Calibration should reduce ECE
    assert ece_calibrated < ece_raw, "Calibration should reduce ECE"
    
    # Target: ECE < 0.10 (from requirements)
    assert ece_calibrated < 0.10, f"ECE should be < 0.10, got {ece_calibrated:.4f}"


if __name__ == "__main__":
    # Run tests with output
    test_calibrator_end_to_end_workflow()
    print("\n" + "="*50 + "\n")
    
    test_calibrator_with_realistic_imbalanced_data()
    print("\n" + "="*50 + "\n")
    
    test_calibrator_comparison_platt_vs_isotonic()
    print("\n" + "="*50 + "\n")
    
    test_calibrator_expected_calibration_error()
