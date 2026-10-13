//! Forces monomorphisation of every mlkem-selkie operation.
//!
//! The crate's API is generic over the parameter set, so a `libmlkem_selkie.rlib` built on its
//! own need not contain every instantiation of the KEM code. `scan-instrs.py` builds this crate
//! instead, for each backend, and disassembles it along with mlkem-selkie and its dependencies.
//!
//! Nothing here needs to run, or even to link. It only needs to exist in the object code.

use mlkem_selkie::{Ciphertext, DecapsulationKey, EncapsulationKey, ParameterSet};

/// Every public operation for one parameter set: key generation, both encapsulations,
/// decapsulation, and (de)serialization of both keys and the ciphertext, which includes the
/// input validation `from_bytes` does on secret keys.
fn exercise<P: ParameterSet>(
    seed: &[u8; 64],
    m: &[u8; 32],
    dk_bytes: &[u8],
    ek_bytes: &[u8],
    ct_bytes: &[u8],
    out: &mut [u8; 32],
) {
    let dk = DecapsulationKey::<P>::generate_derand(seed);
    let (_, ct) = dk.encapsulation_key().encapsulate_derand(m);
    let ss = dk.decapsulate(&ct);
    out.copy_from_slice(ss.as_bytes());

    let random = DecapsulationKey::<P>::generate();
    let (ss, _) = random.encapsulation_key().encapsulate();
    out.copy_from_slice(ss.as_bytes());

    core::hint::black_box(dk.to_bytes());
    core::hint::black_box(dk.encapsulation_key().to_bytes());
    if let (Ok(dk), Ok(ek), Ok(ct)) = (
        DecapsulationKey::<P>::from_bytes(dk_bytes),
        EncapsulationKey::<P>::from_bytes(ek_bytes),
        Ciphertext::<P>::from_bytes(ct_bytes),
    ) {
        core::hint::black_box(ek.to_bytes());
        core::hint::black_box(ct.as_bytes());
        out.copy_from_slice(dk.decapsulate(&ct).as_bytes());
    }
}

/// One exported entry point per parameter set, so that every generic instance is codegen'd.
/// `#[no_mangle]` keeps each one alive; the Rust ABI is fine, since nothing calls them.
macro_rules! probe {
    ($f:ident, $p:ident) => {
        #[no_mangle]
        pub fn $f(
            seed: &[u8; 64],
            m: &[u8; 32],
            dk: &[u8],
            ek: &[u8],
            ct: &[u8],
            out: &mut [u8; 32],
        ) {
            exercise::<mlkem_selkie::$p>(seed, m, dk, ek, ct, out);
        }
    };
}

probe!(probe512, MLKEM512);
probe!(probe768, MLKEM768);
probe!(probe1024, MLKEM1024);
