use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

pub(crate) fn assignment_or_setup<F: Field, T>(
    cs: ConstraintSystemRef<F>,
    setup: impl FnOnce() -> T,
    assign: impl FnOnce() -> Result<T, SynthesisError>,
) -> Result<T, SynthesisError> {
    if cs.is_in_setup_mode() {
        Ok(setup())
    } else {
        assign()
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_relations::gr1cs::{ConstraintSystem, SynthesisError, SynthesisMode};

    #[test]
    fn assignment_or_setup_uses_real_assignment_in_prove_mode() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
            generate_lc_assignments: false,
        });

        let value = super::assignment_or_setup(cs, || 0_u64, || Ok(7_u64)).unwrap();
        assert_eq!(value, 7);
    }

    #[test]
    fn assignment_or_setup_uses_placeholder_in_setup_mode() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Setup);

        let value =
            super::assignment_or_setup(cs, || 11_u64, || Err(SynthesisError::AssignmentMissing))
                .unwrap();
        assert_eq!(value, 11);
    }

    #[test]
    fn assignment_or_setup_keeps_assignment_missing_in_prove_mode() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
            generate_lc_assignments: false,
        });

        let err =
            super::assignment_or_setup(cs, || 0_u64, || Err(SynthesisError::AssignmentMissing))
                .unwrap_err();
        assert!(matches!(err, SynthesisError::AssignmentMissing));
    }
}
