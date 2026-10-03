//! Basic identifiers shared by every component: address families, uplink
//! ids, paths and the FTR field of the mark (SPEC.md §2, §4.2).

use std::fmt;
use std::net::IpAddr;

/// Address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    pub fn of(addr: IpAddr) -> Family {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    /// The configuration key of the family (`ipv4`, `ipv6`).
    pub fn key(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// Stable uplink identifier, 1 to 63 (FR-MARK-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UplinkId(u8);

impl UplinkId {
    pub const MIN: u8 = 1;
    pub const MAX: u8 = 63;

    pub fn new(id: u8) -> Option<UplinkId> {
        (Self::MIN..=Self::MAX).contains(&id).then_some(UplinkId(id))
    }

    pub fn get(self) -> u8 {
        self.0
    }

    /// Every possible id, configured or not (restoration rules, FR-MARK-3).
    pub fn all() -> impl Iterator<Item = UplinkId> {
        (Self::MIN..=Self::MAX).map(UplinkId)
    }
}

impl fmt::Display for UplinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A (uplink, family) pair (SPEC.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathKey {
    pub uplink: UplinkId,
    pub family: Family,
}

/// Value of the FTR field (FR-MARK-2): a class in the two high bits and an
/// uplink id in the six low bits; 0 means "no FTR assignment".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldValue(u8);

impl FieldValue {
    pub const NONE: FieldValue = FieldValue(0);
    /// Class bits of the probe class (also the probe guard selector value).
    pub const PROBE_CLASS: FieldValue = FieldValue(0x40);
    pub const POLICY_BALANCE_CLASS: FieldValue = FieldValue(0x80);
    pub const POLICY_BLOCK_CLASS: FieldValue = FieldValue(0xc0);
    /// Mask of the class bits.
    pub const CLASS_BITS: u8 = 0xc0;

    pub fn path(id: UplinkId) -> FieldValue {
        FieldValue(id.get())
    }

    pub fn probe(id: UplinkId) -> FieldValue {
        FieldValue(0x40 | id.get())
    }

    pub fn policy_balance(id: UplinkId) -> FieldValue {
        FieldValue(0x80 | id.get())
    }

    pub fn policy_block(id: UplinkId) -> FieldValue {
        FieldValue(0xc0 | id.get())
    }

    pub const fn raw(value: u8) -> FieldValue {
        FieldValue(value)
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

/// The 8 contiguous bits of the mark reserved to FTR (`fwmark_mask`, FR-MARK-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FwMask {
    shift: u32,
}

impl FwMask {
    pub const DEFAULT: FwMask = FwMask { shift: 16 };

    /// Accepts a mask of exactly 8 contiguous bits.
    pub fn new(mask: u32) -> Option<FwMask> {
        let shift = mask.trailing_zeros();
        (mask != 0 && mask >> shift == 0xff).then_some(FwMask { shift })
    }

    pub fn mask(self) -> u32 {
        0xff << self.shift
    }

    pub fn shift(self) -> u32 {
        self.shift
    }

    /// `encode(v) = v << trailing_zeros(fwmark_mask)` (FR-MARK-3).
    pub fn encode(self, value: FieldValue) -> u32 {
        u32::from(value.get()) << self.shift
    }

    /// Mask selecting only the class bits of the field.
    pub fn class_mask(self) -> u32 {
        u32::from(FieldValue::CLASS_BITS) << self.shift
    }

    /// The FTR field of a mark.
    pub fn field(self, mark: u32) -> FieldValue {
        FieldValue((mark >> self.shift) as u8)
    }
}

impl Default for FwMask {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_needs_eight_contiguous_bits() {
        assert_eq!(FwMask::new(0x00ff_0000), Some(FwMask::DEFAULT));
        assert_eq!(FwMask::new(0xff).map(FwMask::shift), Some(0));
        assert_eq!(FwMask::new(0xff00_0000).map(FwMask::shift), Some(24));
        for bad in [0, 0x7f, 0x1ff, 0x00ff_0100, 0xf0f0, 0xffff] {
            assert_eq!(FwMask::new(bad), None, "{bad:#x}");
        }
    }

    #[test]
    fn encoding_follows_the_spec_examples() {
        let m = FwMask::DEFAULT;
        let one = UplinkId::new(1).unwrap();
        // FR-MARK-3: the probe value of uplink 1 is 0x00410000/0x00ff0000.
        assert_eq!(m.encode(FieldValue::probe(one)), 0x0041_0000);
        assert_eq!(m.mask(), 0x00ff_0000);
        assert_eq!(m.class_mask(), 0x00c0_0000);
        assert_eq!(m.field(0x1241_0034), FieldValue::probe(one));
        let top = FwMask::new(0xff00_0000).unwrap();
        assert_eq!(
            top.encode(FieldValue::policy_block(UplinkId::new(63).unwrap())),
            0xff00_0000
        );
    }

    #[test]
    fn uplink_ids_are_one_to_sixty_three() {
        assert!(UplinkId::new(0).is_none());
        assert!(UplinkId::new(64).is_none());
        assert_eq!(UplinkId::all().count(), 63);
    }
}
