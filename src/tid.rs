//! The layout of a transaction id this node allocates, and how an instance
//! index is carried in it.
//!
//! A node that originates dialogues allocates a 4-octet OTID (Q.773). When the
//! function runs as several instances behind one global title, the peer
//! addresses every later message of the dialogue (TC-CONTINUE / TC-END /
//! TC-ABORT) with that OTID as the DTID, and an STP relaying it can tell which
//! instance holds the dialogue from the id alone. The layout, most significant
//! bit first:
//!
//! ```text
//!  1 bit              `bits` bits         31 - `bits` bits
//! +--------+-------------------------+-----------------------+
//! | marker |   instance (0..2^bits)  |  per-instance counter |
//! +--------+-------------------------+-----------------------+
//! ```
//!
//! The marker bit is always set (it keeps an id of ours apart from a small
//! peer OTID). With `bits == 0` there is no instance field and the layout is
//! the marker followed by a 31-bit counter.

/// The widest instance field: it leaves a 15-bit counter per instance.
pub const MAX_INSTANCE_BITS: u8 = 16;

const MARKER: u32 = 0x8000_0000;

/// Compose an id from an instance index and a counter. The counter is truncated
/// to the bits the instance field leaves; an instance beyond the field's width
/// is truncated too (config validation rejects one before it gets here).
pub fn compose(bits: u8, instance: u32, counter: u32) -> u32 {
    let bits = u32::from(bits.min(MAX_INSTANCE_BITS));
    let counter_bits = 31 - bits;
    let counter_mask = (1u32 << counter_bits) - 1;
    let instance_mask = (1u32 << bits) - 1;
    MARKER | ((instance & instance_mask) << counter_bits) | (counter & counter_mask)
}

/// The instance index carried in a transaction id, or `None` when the id is not
/// one of ours: not 4 octets, or without the marker bit.
pub fn instance_of(tid: &[u8], bits: u8) -> Option<u32> {
    let bits = u32::from(bits.min(MAX_INSTANCE_BITS));
    let raw: [u8; 4] = tid.try_into().ok()?;
    let value = u32::from_be_bytes(raw);
    if value & MARKER == 0 {
        return None;
    }
    let counter_bits = 31 - bits;
    Some((value >> counter_bits) & ((1u32 << bits) - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_an_instance_field_the_id_is_the_marker_and_the_counter() {
        // The layout this node has always used.
        assert_eq!(compose(0, 0, 1), 0x8000_0001);
        assert_eq!(compose(0, 0, 0x7fff_ffff), 0xffff_ffff);
    }

    #[test]
    fn four_bit_instance_sits_right_under_the_marker() {
        // marker | 0b0010 | counter 5 in the low 27 bits
        assert_eq!(compose(4, 2, 5), 0x8000_0000 | (2 << 27) | 5);
        assert_eq!(compose(4, 2, 5), 0x9000_0005);
    }

    #[test]
    fn the_instance_reads_back_from_the_id() {
        for instance in 0..16 {
            let tid = compose(4, instance, 12345).to_be_bytes();
            assert_eq!(instance_of(&tid, 4), Some(instance));
        }
        let tid = compose(8, 200, u32::MAX).to_be_bytes();
        assert_eq!(instance_of(&tid, 8), Some(200));
    }

    #[test]
    fn a_counter_never_spills_into_the_instance_field() {
        let tid = compose(4, 3, u32::MAX).to_be_bytes();
        assert_eq!(instance_of(&tid, 4), Some(3));
    }

    #[test]
    fn an_id_that_is_not_ours_has_no_instance() {
        assert_eq!(instance_of(&[0x00, 0x00, 0x00, 0x07], 4), None); // no marker
        assert_eq!(instance_of(&[0x90, 0x00, 0x05], 4), None); // 3 octets
        assert_eq!(instance_of(&[], 4), None);
    }
}
