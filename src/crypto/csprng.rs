use rand_core::{OsRng, RngCore};

pub(crate) fn fill_bytes(bytes: &mut [u8]) {
    OsRng.fill_bytes(bytes);
}
