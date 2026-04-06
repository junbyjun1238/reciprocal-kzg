use super::*;

macro_rules! impl_binary_op {
    (
        $trait: ident,
        $fn: ident,
        |$lhs_i:tt : &$lhs:ty, $rhs_i:tt : &$rhs:ty| -> $out:ty $body:block,
        ($($params:tt)+),
    ) => {
        impl<$($params)+> core::ops::$trait<&$rhs> for &$lhs {
            type Output = $out;

            fn $fn(self, other: &$rhs) -> Self::Output {
                let $lhs_i = self;
                let $rhs_i = other;
                $body
            }
        }

        impl<$($params)+> core::ops::$trait<$rhs> for &$lhs {
            type Output = $out;

            fn $fn(self, other: $rhs) -> Self::Output {
                core::ops::$trait::$fn(self, &other)
            }
        }

        impl<$($params)+> core::ops::$trait<&$rhs> for $lhs {
            type Output = $out;

            fn $fn(self, other: &$rhs) -> Self::Output {
                core::ops::$trait::$fn(&self, other)
            }
        }

        impl<$($params)+> core::ops::$trait<$rhs> for $lhs {
            type Output = $out;

            fn $fn(self, other: $rhs) -> Self::Output {
                core::ops::$trait::$fn(&self, &other)
            }
        }
    };
}

macro_rules! impl_assignment_op {
    (
        $assign_trait: ident,
        $assign_fn: ident,
        |$lhs_i:tt : &mut $lhs:ty, $rhs_i:tt : &$rhs:ty| $body:block,
        ($($params:tt)+),
    ) => {
        impl<$($params)+> core::ops::$assign_trait<$rhs> for $lhs {
            fn $assign_fn(&mut self, other: $rhs) {
                core::ops::$assign_trait::$assign_fn(self, &other)
            }
        }

        impl<$($params)+> core::ops::$assign_trait<&$rhs> for $lhs {
            fn $assign_fn(&mut self, other: &$rhs) {
                let $lhs_i = self;
                let $rhs_i = other;
                $body
            }
        }
    };
}

impl_binary_op!(
    Add,
    add,
    |a: &LimbedVar<F, Cfg, LHS_ALIGNED>, b: &LimbedVar<F, Cfg, RHS_ALIGNED>| -> LimbedVar<F, Cfg, false> {
        a.add_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const LHS_ALIGNED: bool, const RHS_ALIGNED: bool),
);

impl_assignment_op!(
    AddAssign,
    add_assign,
    |a: &mut LimbedVar<F, Cfg, false>, b: &LimbedVar<F, Cfg, ALIGNED>| {
        *a = a.add_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const ALIGNED: bool),
);

impl_binary_op!(
    Sub,
    sub,
    |a: &LimbedVar<F, Cfg, SELF_ALIGNED>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| -> LimbedVar<F, Cfg, false> {
        a.sub_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const SELF_ALIGNED: bool, const OTHER_ALIGNED: bool),
);

impl_assignment_op!(
    SubAssign,
    sub_assign,
    |a: &mut LimbedVar<F, Cfg, false>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| {
        *a = a.sub_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const OTHER_ALIGNED: bool),
);

impl_binary_op!(
    Mul,
    mul,
    |a: &LimbedVar<F, Cfg, SELF_ALIGNED>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| -> LimbedVar<F, Cfg, false> {
        a.mul_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const SELF_ALIGNED: bool, const OTHER_ALIGNED: bool),
);

impl_assignment_op!(
    MulAssign,
    mul_assign,
    |a: &mut LimbedVar<F, Cfg, false>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| {
        *a = a.mul_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const OTHER_ALIGNED: bool),
);
