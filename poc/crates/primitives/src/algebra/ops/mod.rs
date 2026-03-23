//! This module collects common algebraic operation traits and their in-circuit
//! gadgets, including:
//!
//! * [`bits`]: conversions between bit representations and algebraic variables.
//! * [`eq`]: generalization of equality checks.
//! * [`matrix`]: sparse matrix representation and operations.
//! * [`poly`]: helpers for polynomial operations.
//! * [`pow`]: computation of powers.
//! * [`rlc`]: random linear combinations.
//! * [`vector`]: vector operations.

pub mod bits;
pub mod eq;
pub mod matrix;
pub mod poly;
pub mod pow;
pub mod rlc;
pub mod vector;
