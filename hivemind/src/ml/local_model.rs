/// Local NIDS (Network Intrusion Detection System) model.
///
/// A lightweight single-hidden-layer neural network trained on local
/// packet telemetry features. The model classifies traffic as benign
/// or malicious based on a feature vector derived from eBPF sensor data.
///
/// # Privacy Invariant
/// Training data stays local. Only encrypted gradients leave the node.
///
/// # Architecture
/// Input (FL_FEATURE_DIM) → Hidden (FL_HIDDEN_DIM, ReLU) → Output (1, Sigmoid)
///
/// Features: packet_size, entropy, port, protocol, flags, JA4 components,
/// timing statistics, connection patterns, etc.
use common::hivemind;
use tracing::{debug, info};

/// A simple feedforward neural network for intrusion detection.
///
/// Two-layer perceptron: input → hidden (ReLU) → output (sigmoid).
/// Weights are stored as flat vectors for easy serialization and
/// federated aggregation.
pub struct LocalModel {
    /// Weights for input → hidden layer. Shape: [FL_HIDDEN_DIM × FL_FEATURE_DIM].
    weights_ih: Vec<f32>,
    /// Bias for hidden layer. Shape: [FL_HIDDEN_DIM].
    bias_h: Vec<f32>,
    /// Weights for hidden → output layer. Shape: [FL_HIDDEN_DIM].
    weights_ho: Vec<f32>,
    /// Bias for output layer. Scalar.
    bias_o: f32,
    /// Cached hidden activations from last forward pass (for backprop).
    last_hidden: Vec<f32>,
    /// Cached input from last forward pass (for backprop).
    last_input: Vec<f32>,
    /// Cached output from last forward pass (for backprop).
    last_output: f32,
    /// Learning rate for SGD.
    learning_rate: f32,
}

impl LocalModel {
    /// Create a new model with Xavier-initialized weights.
    ///
    /// Xavier initialization: weights ~ U(-sqrt(6/(fan_in+fan_out)), sqrt(6/(fan_in+fan_out)))
    /// We use a deterministic seed for reproducibility in tests.
    pub fn new(learning_rate: f32) -> Self {
        let input_dim = hivemind::FL_FEATURE_DIM;
        let hidden_dim = hivemind::FL_HIDDEN_DIM;

        // Xavier scale factors
        let scale_ih = (6.0_f32 / (input_dim + hidden_dim) as f32).sqrt();
        let scale_ho = (6.0_f32 / (hidden_dim + 1) as f32).sqrt();

        // Initialize with simple deterministic pattern
        // ARCH: In production, use rand crate for proper Xavier init
        let weights_ih: Vec<f32> = (0..hidden_dim * input_dim)
            .map(|i| {
                let t = (i as f32 * 0.618034) % 1.0; // golden ratio spacing
                (t * 2.0 - 1.0) * scale_ih
            })
            .collect();

        let bias_h = vec![0.0_f32; hidden_dim];

        let weights_ho: Vec<f32> = (0..hidden_dim)
            .map(|i| {
                let t = (i as f32 * 0.618034) % 1.0;
                (t * 2.0 - 1.0) * scale_ho
            })
            .collect();

        let bias_o = 0.0_f32;

        info!(
            input_dim,
            hidden_dim,
            total_params = weights_ih.len() + bias_h.len() + weights_ho.len() + 1,
            "Local NIDS model initialized"
        );

        Self {
            weights_ih,
            bias_h,
            weights_ho,
            bias_o,
            last_hidden: vec![0.0; hidden_dim],
            last_input: vec![0.0; input_dim],
            last_output: 0.0,
            learning_rate,
        }
    }

    /// Forward pass: input features → maliciousness probability [0, 1].
    ///
    /// Caches intermediate values for subsequent backward pass.
    pub fn forward(&mut self, input: &[f32]) -> f32 {
        let input_dim = hivemind::FL_FEATURE_DIM;
        let hidden_dim = hivemind::FL_HIDDEN_DIM;

        assert_eq!(input.len(), input_dim, "Input dimension mismatch");

        // Cache input for backprop
        self.last_input.copy_from_slice(input);

        // Hidden layer: ReLU(W_ih × input + b_h)
        for h in 0..hidden_dim {
            let mut sum = self.bias_h[h];
            for (i, &inp) in input.iter().enumerate() {
                sum += self.weights_ih[h * input_dim + i] * inp;
            }
            self.last_hidden[h] = relu(sum);
        }

        // Output layer: sigmoid(W_ho × hidden + b_o)
        let mut out = self.bias_o;
        for h in 0..hidden_dim {
            out += self.weights_ho[h] * self.last_hidden[h];
        }
        self.last_output = sigmoid(out);

        debug!(output = self.last_output, "Forward pass complete");
        self.last_output
    }

    /// Backward pass: compute gradients given the target label.
    ///
    /// Uses binary cross-entropy loss. Returns gradients as a flat vector
    /// in the same order as `get_weights()` for federated aggregation.
    ///
    /// # Returns
    /// Gradient vector: [d_weights_ih, d_bias_h, d_weights_ho, d_bias_o]
    pub fn backward(&self, target: f32) -> Vec<f32> {
        let input_dim = hivemind::FL_FEATURE_DIM;
        let hidden_dim = hivemind::FL_HIDDEN_DIM;

        // Output gradient: dL/d_out = output - target (BCE derivative)
        let d_out = self.last_output - target;

        // Gradients for hidden→output weights
        let d_weights_ho: Vec<f32> = self.last_hidden
            .iter()
            .map(|&hid| d_out * hid)
            .collect();
        let d_bias_o = d_out;

        // Backprop through hidden layer
        let mut d_weights_ih = vec![0.0_f32; hidden_dim * input_dim];
        let mut d_bias_h = vec![0.0_f32; hidden_dim];

        for h in 0..hidden_dim {
            // dL/d_hidden[h] = d_out * w_ho[h] * relu'(pre_activation)
            let relu_grad = if self.last_hidden[h] > 0.0 { 1.0 } else { 0.0 };
            let d_hidden = d_out * self.weights_ho[h] * relu_grad;

            d_bias_h[h] = d_hidden;
            for i in 0..input_dim {
                d_weights_ih[h * input_dim + i] = d_hidden * self.last_input[i];
            }
        }

        // Pack gradients in canonical order
        let total = input_dim * hidden_dim + hidden_dim + hidden_dim + 1;
        let mut grads = Vec::with_capacity(total);
        grads.extend_from_slice(&d_weights_ih);
        grads.extend_from_slice(&d_bias_h);
        grads.extend_from_slice(&d_weights_ho);
        grads.push(d_bias_o);
        grads
    }

    /// Apply gradients to update model weights (SGD step).
    pub fn apply_gradients(&mut self, gradients: &[f32]) {
        let input_dim = hivemind::FL_FEATURE_DIM;
        let hidden_dim = hivemind::FL_HIDDEN_DIM;
        let expected = input_dim * hidden_dim + hidden_dim + hidden_dim + 1;

        assert_eq!(gradients.len(), expected, "Gradient dimension mismatch");

        let mut offset = 0;

        // Update weights_ih
        for w in &mut self.weights_ih {
            *w -= self.learning_rate * gradients[offset];
            offset += 1;
        }

        // Update bias_h
        for b in &mut self.bias_h {
            *b -= self.learning_rate * gradients[offset];
            offset += 1;
        }

        // Update weights_ho
        for w in &mut self.weights_ho {
            *w -= self.learning_rate * gradients[offset];
            offset += 1;
        }

        // Update bias_o
        self.bias_o -= self.learning_rate * gradients[offset];

        debug!("Model weights updated via SGD");
    }

    /// Get all model weights as a flat vector.
    ///
    /// Order: [weights_ih, bias_h, weights_ho, bias_o]
    pub fn get_weights(&self) -> Vec<f32> {
        let total = self.weights_ih.len() + self.bias_h.len()
            + self.weights_ho.len() + 1;
        let mut weights = Vec::with_capacity(total);
        weights.extend_from_slice(&self.weights_ih);
        weights.extend_from_slice(&self.bias_h);
        weights.extend_from_slice(&self.weights_ho);
        weights.push(self.bias_o);
        weights
    }

    /// Replace all model weights from a flat vector.
    ///
    /// Used to apply aggregated weights from federated learning.
    pub fn set_weights(&mut self, weights: &[f32]) {
        let input_dim = hivemind::FL_FEATURE_DIM;
        let hidden_dim = hivemind::FL_HIDDEN_DIM;
        let expected = input_dim * hidden_dim + hidden_dim + hidden_dim + 1;

        assert_eq!(weights.len(), expected, "Weight dimension mismatch");

        let mut offset = 0;
        self.weights_ih.copy_from_slice(&weights[offset..offset + input_dim * hidden_dim]);
        offset += input_dim * hidden_dim;
        self.bias_h.copy_from_slice(&weights[offset..offset + hidden_dim]);
        offset += hidden_dim;
        self.weights_ho.copy_from_slice(&weights[offset..offset + hidden_dim]);
        offset += hidden_dim;
        self.bias_o = weights[offset];
    }

    /// Total number of trainable parameters.
    pub fn param_count(&self) -> usize {
        self.weights_ih.len() + self.bias_h.len() + self.weights_ho.len() + 1
    }
}

/// ReLU activation function.
fn relu(x: f32) -> f32 {
    if x > 0.0 { x } else { 0.0 }
}

/// Sigmoid activation function.
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_creation() {
        let model = LocalModel::new(0.01);
        let expected_params = hivemind::FL_FEATURE_DIM * hivemind::FL_HIDDEN_DIM
            + hivemind::FL_HIDDEN_DIM
            + hivemind::FL_HIDDEN_DIM
            + 1;
        assert_eq!(model.param_count(), expected_params);
    }

    #[test]
    fn forward_pass_produces_probability() {
        let mut model = LocalModel::new(0.01);
        let input = vec![0.5_f32; hivemind::FL_FEATURE_DIM];
        let output = model.forward(&input);
        assert!(output >= 0.0 && output <= 1.0, "Output {output} not in [0,1]");
    }

    #[test]
    fn backward_pass_produces_correct_gradient_size() {
        let mut model = LocalModel::new(0.01);
        let input = vec![1.0_f32; hivemind::FL_FEATURE_DIM];
        model.forward(&input);
        let grads = model.backward(1.0);
        assert_eq!(grads.len(), model.param_count());
    }

    #[test]
    fn training_reduces_loss() {
        let mut model = LocalModel::new(0.1);
        let input = vec![1.0_f32; hivemind::FL_FEATURE_DIM];
        let target = 1.0;

        // Initial prediction
        let pred0 = model.forward(&input);
        let loss0 = -(target * pred0.ln() + (1.0 - target) * (1.0 - pred0).ln());

        // One SGD step
        let grads = model.backward(target);
        model.apply_gradients(&grads);

        // Prediction after training
        let pred1 = model.forward(&input);
        let loss1 = -(target * pred1.ln() + (1.0 - target) * (1.0 - pred1).ln());

        assert!(
            loss1 < loss0,
            "Loss should decrease after SGD: {loss0} → {loss1}"
        );
    }

    #[test]
    fn get_set_weights_roundtrip() {
        let model = LocalModel::new(0.01);
        let weights = model.get_weights();

        let mut model2 = LocalModel::new(0.01);
        model2.set_weights(&weights);

        assert_eq!(model.get_weights(), model2.get_weights());
    }

    #[test]
    fn sigmoid_range() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(100.0) > 0.999);
        assert!(sigmoid(-100.0) < 0.001);
    }
}
