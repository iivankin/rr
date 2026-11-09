//! What the CPU has of the instructions the components use, asked once
//! for the process: what the target promises, and on aarch64 Linux and
//! Windows and on x86_64 what the CPU says it has besides. A component
//! asks has() before it runs code built for more than its target, of
//! Features that only the constants here name (AES, SHA256, SHA512,
//! WIDE_AES, and sets of them by and).

mod sys;

pub use sys::*;

#[cfg(test)]
mod tests {
    use super::{AES, SHA256, SHA512, WIDE_AES, has};

    /// As a component asks: the same answer every time, and a set of
    /// features is had when each of them is.
    #[test]
    fn asks() {
        for feature in [&AES, &SHA256, &SHA512, &WIDE_AES] {
            assert_eq!(has(feature), has(feature));
        }
        assert_eq!(has(&AES.and(&SHA512)), has(&AES) && has(&SHA512));
        assert_eq!(has(&SHA256.and(&WIDE_AES)), has(&SHA256) && has(&WIDE_AES));
        // What the target promises, the CPU has.
        if cfg!(all(target_arch = "aarch64", target_feature = "aes")) {
            assert!(has(&AES));
        }
    }
}
