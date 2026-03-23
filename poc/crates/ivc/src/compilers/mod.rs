//! Compilers that transform a folding scheme into a full IVC scheme.
//!
//! We currently provide a compiler based on CycleFold, and in the future there
//! may be other compilers such as the naive one (on a single curve) which fits
//! well with hash-based folding schemes and the two curves one.

pub mod cyclefold;
