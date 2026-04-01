//! Behavioral engine: per-IP state machine for threat progression tracking.
//!
//! Each source IP gets a `BehaviorProfile` that tracks packet statistics,
//! connection patterns, and a phase in the threat lifecycle. Transitions
//! are driven by deterministic thresholds (fast path) with optional
//! LLM-assisted classification (slow path).

mod profile;
mod transitions;

pub use profile::{BehaviorPhase, BehaviorProfile};
pub use transitions::{TransitionVerdict, evaluate_transitions};
