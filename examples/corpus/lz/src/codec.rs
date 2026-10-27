//! An LZ77 codec in sequences, as LZ4 lays them out. A sequence is a
//! token byte, whose high four bits are the count of literals and low
//! four the match length less MIN_MATCH, each 15 continued in bytes of
//! up to 255; then the literals; then the match's offset back into the
//! output, u16 little-endian. The last sequence has literals only.

use alloc::vec::Vec;

/// The shortest match worth a sequence.
pub const MIN_MATCH: usize = 4;
/// How far back a match may start.
pub const WINDOW: usize = 65535;
/// The longest input compressed as one block.
pub const BLOCK_MAX: usize = 1 << 20;
/// Bits of the match finder's hash.
const HASH_BITS: u32 = 12;

const _: () = assert!(WINDOW <= u16::MAX as usize);

/// Why decompression stopped.
pub enum Error {
    /// The input ends inside a sequence.
    Truncated,
    /// A match reaches back before the output's start, or to nowhere.
    BadOffset,
    /// The output would pass the limit the caller set.
    TooLong,
}

/// The compressor's state: where each hash of four bytes was seen last.
/// Made once and reused for every block.
pub struct Compressor {
    table: [u32; 1 << HASH_BITS],
}

impl Default for Compressor {
    fn default() -> Compressor {
        Compressor::new()
    }
}

/// The hash of four bytes.
fn hash(p: [u8; MIN_MATCH]) -> usize {
    let v = u32::from_le_bytes(p);
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// Append a length's continuation: n past the 15 in the token, in bytes
/// of 255 and a last one below it.
fn put_length(out: &mut Vec<u8>, mut n: usize) {
    while n >= 255 {
        // rr: escape(alloc): a block's output is bounded by its input, at
        // most BLOCK_MAX bytes, which compress checks.
        out.push(255);
        n -= 255;
    }
    // rr: escape(alloc): bounded as the block is.
    out.push(u8::try_from(n).unwrap_or(u8::MAX));
}

/// One sequence: literals, then a match of len at offset, or none.
fn put_sequence(out: &mut Vec<u8>, literals: &[u8], matched: Option<(usize, u16)>) {
    let lit = literals.len();
    let (len, offset) = matched.unwrap_or((MIN_MATCH, 0));
    let m = len - MIN_MATCH;
    let high = u8::try_from(lit.min(15)).unwrap_or(15);
    let low = u8::try_from(m.min(15)).unwrap_or(15);
    let token = (high << 4) | low;
    // rr: escape(alloc): a block's output is bounded by its input, at most
    // BLOCK_MAX bytes, which compress checks.
    out.push(token);
    if lit >= 15 {
        put_length(out, lit - 15);
    }
    // rr: escape(copy): literals are the input's bytes, written into the
    // block as the format has them.
    out.extend_from_slice(literals);
    if matched.is_some() {
        // rr: escape(alloc): bounded as the block is.
        out.extend_from_slice(&offset.to_le_bytes());
        if m >= 15 {
            put_length(out, m - 15);
        }
    }
}

impl Compressor {
    pub fn new() -> Compressor {
        Compressor {
            table: [0; 1 << HASH_BITS],
        }
    }

    /// input, at most BLOCK_MAX bytes, compressed onto out.
    #[cfg_attr(rr, rr::hot)]
    pub fn compress(&mut self, input: &[u8], out: &mut Vec<u8>) {
        assert!(input.len() <= BLOCK_MAX);
        self.table.fill(0);
        let mut anchor = 0;
        let mut i = 0;
        while i + MIN_MATCH <= input.len() {
            let Some(four) = input.get(i..).and_then(<[u8]>::first_chunk::<MIN_MATCH>) else {
                break;
            };
            let Ok(pos) = u32::try_from(i) else {
                break;
            };
            // rr: escape(panic): hash is below 1 << HASH_BITS, the table's length.
            let slot = &mut self.table[hash(*four)];
            let candidate = *slot as usize;
            *slot = pos;
            if let Ok(back) = u16::try_from(i - candidate)
                && candidate < i
                && input.get(candidate..candidate + MIN_MATCH) == Some(&four[..])
            {
                let mut len = MIN_MATCH;
                while i + len < input.len() && input.get(candidate + len) == input.get(i + len) {
                    len += 1;
                }
                // rr: escape(panic): anchor <= i < input.len(): anchor only
                // moves up to i.
                put_sequence(out, &input[anchor..i], Some((len, back)));
                i += len;
                anchor = i;
            } else {
                i += 1;
            }
        }
        // rr: escape(panic): anchor <= input.len(): it moves only to i, and
        // the last match ends inside input.
        put_sequence(out, &input[anchor..], None);
    }
}

/// A length's continuation at input[*at..], added to base.
fn get_length(input: &[u8], at: &mut usize, base: usize) -> Result<usize, Error> {
    let mut n = base;
    while let Some(&b) = input.get(*at) {
        *at += 1;
        n += usize::from(b);
        if b != 255 {
            return Ok(n);
        }
    }
    Err(Error::Truncated)
}

/// input decompressed onto out, which may grow by at most max bytes.
#[cfg_attr(rr, rr::hot)]
pub fn decompress(input: &[u8], out: &mut Vec<u8>, max: usize) -> Result<(), Error> {
    // What this call has written onto out.
    let mut written = 0;
    let mut at = 0;
    while let Some(&token) = input.get(at) {
        at += 1;
        let mut lit = usize::from(token >> 4);
        if lit == 15 {
            lit = get_length(input, &mut at, 15)?;
        }
        let literals = input.get(at..at + lit).ok_or(Error::Truncated)?;
        if written + lit > max {
            return Err(Error::TooLong);
        }
        // rr: escape(copy): literals go from the block into the output, as
        // decompressing means.
        out.extend_from_slice(literals);
        written += lit;
        at += lit;
        if at == input.len() {
            return Ok(());
        }
        let o = input
            .get(at..)
            .and_then(<[u8]>::first_chunk::<2>)
            .ok_or(Error::Truncated)?;
        let offset = usize::from(u16::from_le_bytes(*o));
        at += 2;
        let mut len = usize::from(token & 15) + MIN_MATCH;
        if len == 15 + MIN_MATCH {
            len = get_length(input, &mut at, len)?;
        }
        if offset == 0 || offset > written {
            return Err(Error::BadOffset);
        }
        if written + len > max {
            return Err(Error::TooLong);
        }
        written += len;
        // A match may overlap what it writes: copy a byte at a time.
        // rr: escape(panic): offset <= written <= out.len(), checked above.
        let from = out.len() - offset;
        for k in 0..len {
            // rr: escape(panic): from + k < out.len(): offset >= 1, and
            // out grows by a byte each turn.
            let b = out[from + k];
            // rr: escape(copy): a match repeats earlier output, which is what
            // the format stores in its place.
            out.push(b);
        }
    }
    Ok(())
}

/// Any bytes: decompressed, refused or within the limit; compressed, they
/// come back as they went in.
#[cfg(fuzzing)]
pub fn fuzz_codec(input: &[u8]) {
    let mut out = Vec::new();
    if decompress(input, &mut out, 1 << 16).is_ok() {
        assert!(out.len() <= 1 << 16);
    }
    let mut packed = Vec::new();
    Compressor::new().compress(input, &mut packed);
    out.clear();
    assert!(decompress(&packed, &mut out, input.len()).is_ok());
    assert!(out == input);
}

#[cfg(test)]
mod tests {
    use super::{Compressor, decompress};
    use alloc::vec::Vec;
    use test::Bencher;

    /// input compressed and decompressed again equals itself.
    fn roundtrip(input: &[u8]) {
        let mut packed = Vec::new();
        Compressor::new().compress(input, &mut packed);
        let mut back = Vec::new();
        assert!(decompress(&packed, &mut back, input.len()).is_ok());
        assert!(back == input);
    }

    fn text() -> Vec<u8> {
        let mut text = Vec::new();
        for _ in 0..200 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        text
    }

    #[test]
    fn roundtrips() {
        roundtrip(b"");
        roundtrip(b"abc");
        roundtrip(&[b'a'; 1000]);
        roundtrip(&text());
        // Bytes from a linear congruential generator: nothing to match.
        let mut noise = Vec::new();
        let mut x: u32 = 1;
        for _ in 0..5000 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            // rr: escape(cast): the generator's middle bits are its most random.
            noise.push(x.to_le_bytes()[2]);
        }
        roundtrip(&noise);
    }

    #[test]
    fn text_shrinks() {
        let text = text();
        let mut packed = Vec::new();
        Compressor::new().compress(&text, &mut packed);
        assert!(packed.len() < text.len() / 4);
    }

    #[test]
    fn damaged_input_is_refused() {
        let text = text();
        let mut packed = Vec::new();
        Compressor::new().compress(&text, &mut packed);
        let mut out = Vec::new();
        assert!(decompress(&packed, &mut out, 100).is_err());
        out.clear();
        assert!(decompress(&packed[..packed.len() / 2], &mut out, text.len()).is_err());
        out.clear();
        // A match that reaches back before the start.
        assert!(decompress(&[0x10, b'a', 9, 0], &mut out, 100).is_err());
    }

    /// A block of text compressed into a buffer that is reused.
    #[bench]
    fn compress_text(b: &mut Bencher) {
        let text = text();
        let mut c = Compressor::new();
        let mut packed = Vec::new();
        b.iter(|| {
            packed.clear();
            c.compress(&text, &mut packed);
        });
    }

    /// The same block decompressed into a buffer that is reused.
    #[bench]
    fn decompress_text(b: &mut Bencher) {
        let text = text();
        let mut packed = Vec::new();
        Compressor::new().compress(&text, &mut packed);
        let mut out = Vec::new();
        b.iter(|| {
            out.clear();
            decompress(&packed, &mut out, text.len()).is_ok()
        });
    }
}
