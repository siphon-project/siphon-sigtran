//! Thin helpers over [`mtp3::PointCode`], decimal-first parsing keyed by a
//! node/tenant [`Variant`].
//!
//! Point codes in `sigtran.yaml` are written **decimal** (`1000`, `2000`), the
//! way an operator reads them off a plan, not in the structured `a-b-c` dotted
//! form. The config deserialises them as bare integers ([`RawPc`]); a
//! [`Variant`] from the owning node/tenant then resolves each into a real
//! [`mtp3::PointCode`] via [`resolve`]. Keeping the two steps apart is what lets
//! one tenant be ITU and another ANSI in the same file, the same integer means
//! different things under different variants.

use serde::Deserialize;

pub use mtp3::{PointCode, PointCodeError, Variant};

/// A point code as it appears in the config: a bare decimal integer, still
/// **unresolved** because its width/variant comes from the owning node or
/// tenant, not the number itself.
///
/// `#[serde(transparent)]` so `point_code: 1000` in YAML deserialises straight
/// into `RawPc(1000)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(transparent)]
pub struct RawPc(pub u32);

impl RawPc {
    /// Resolve this decimal value into a typed [`PointCode`] under `variant`,
    /// validating it fits the variant's bit width.
    pub fn resolve(self, variant: Variant) -> Result<PointCode, PointCodeError> {
        PointCode::from_value(self.0, variant)
    }
}

impl From<u32> for RawPc {
    fn from(v: u32) -> Self {
        RawPc(v)
    }
}

/// Resolve a decimal point-code value under a [`Variant`]. Shorthand for
/// [`PointCode::from_value`] that reads decimal-first at call sites.
pub fn resolve(value: u32, variant: Variant) -> Result<PointCode, PointCodeError> {
    PointCode::from_value(value, variant)
}

/// Parse a point code that may be decimal (`"1000"`) or structured
/// (`"2-1-3"`) under `variant`. Delegates to [`PointCode::parse`], which
/// accepts both forms.
pub fn parse(s: &str, variant: Variant) -> Result<PointCode, PointCodeError> {
    PointCode::parse(s, variant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_pc_resolves_decimal_under_variant() {
        let pc = RawPc(1000).resolve(Variant::Itu).unwrap();
        assert_eq!(pc.value(), 1000);
        assert_eq!(pc.variant(), Variant::Itu);
    }

    #[test]
    fn same_decimal_differs_by_variant() {
        // 5000 is valid under both ITU (14-bit) and ANSI (24-bit) but the
        // typed point codes are not equal, the variant is part of identity.
        let itu = RawPc(5000).resolve(Variant::Itu).unwrap();
        let ansi = RawPc(5000).resolve(Variant::Ansi).unwrap();
        assert_ne!(itu, ansi);
    }

    #[test]
    fn rejects_out_of_range_for_variant() {
        // 20000 > 0x3FFF (ITU max) → error under ITU, fine under ANSI.
        assert!(RawPc(20_000).resolve(Variant::Itu).is_err());
        assert!(RawPc(20_000).resolve(Variant::Ansi).is_ok());
    }

    #[test]
    fn parse_accepts_decimal_and_structured() {
        assert_eq!(parse("1000", Variant::Itu).unwrap().value(), 1000);
        assert_eq!(parse("2-1-3", Variant::Itu).unwrap().value(), 4107);
    }
}
