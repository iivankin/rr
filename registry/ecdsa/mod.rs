//! ECDSA signature verification on P-256 and P-384 (FIPS 186-4, SEC 1
//! 4.1.4). Everything it reads is public: the key, the hash and the
//! signature. So the arithmetic is not constant time, but every length
//! an attacker picks is checked before it is used.
//!
//! Field elements are little-endian 64-bit limbs in Montgomery form,
//! multiplied and reduced (Montgomery) against each modulus as a
//! constant, so that the compiler unrolls four limbs for P-256 and six
//! for P-384; P-256's reduction is shifts of its special prime. Points
//! are Jacobian; u1 G + u2 Q is one run of doublings over both scalars
//! in NAF, G's multiples a constant table.

/// Limbs of the widest number, P-384's.
const LIMBS: usize = 6;
/// The digits of a NAF of a scalar below 2^384, one more than its bits.
const DIGITS: usize = 64 * LIMBS + 1;
/// Odd multiples P, 3P, ..., 15P that a width-5 NAF picks from.
const TABLE: usize = 8;
/// The odd multiples of P-256's G, for width 7.
const BASE_P256: usize = 32;

/// A number below 2^384; P-256's use the low four limbs.
type Fe = [u64; LIMBS];

/// The curves this verifies on.
pub enum Curve {
    P256,
    P384,
}

/// A modulus and what Montgomery multiplication by it needs.
struct Modulus {
    m: Fe,
    /// -m^-1 mod 2^64.
    m0inv: u64,
    /// R^2 mod m, with R = 2^(64 limbs), to bring a number in.
    rr: Fe,
}

/// A curve y^2 = x^3 - 3x + b over the field of p, with a base point G
/// of prime order n, whose multiples are in a table below; the values
/// are FIPS 186-4's, plain.
struct Params {
    p: Modulus,
    n: Modulus,
    b: Fe,
    /// Bytes of a coordinate and of a scalar.
    bytes: usize,
}

/// A point (x, y) in Montgomery form.
struct Affine {
    x: Fe,
    y: Fe,
}

/// A point in Jacobian coordinates, (X / Z^2, Y / Z^3), in Montgomery
/// form; Z = 0 is the point at infinity.
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

const P256: Params = Params {
    p: Modulus {
        m: [
            0xffffffffffffffff,
            0x00000000ffffffff,
            0x0000000000000000,
            0xffffffff00000001,
            0,
            0,
        ],
        m0inv: 0x0000000000000001,
        rr: [
            0x0000000000000003,
            0xfffffffbffffffff,
            0xfffffffffffffffe,
            0x00000004fffffffd,
            0,
            0,
        ],
    },
    n: Modulus {
        m: [
            0xf3b9cac2fc632551,
            0xbce6faada7179e84,
            0xffffffffffffffff,
            0xffffffff00000000,
            0,
            0,
        ],
        m0inv: 0xccd1c8aaee00bc4f,
        rr: [
            0x83244c95be79eea2,
            0x4699799c49bd6fa6,
            0x2845b2392b6bec59,
            0x66e12d94f3d95620,
            0,
            0,
        ],
    },
    b: [
        0x3bce3c3e27d2604b,
        0x651d06b0cc53b0f6,
        0xb3ebbd55769886bc,
        0x5ac635d8aa3a93e7,
        0,
        0,
    ],
    bytes: 32,
};

const P384: Params = Params {
    p: Modulus {
        m: [
            0x00000000ffffffff,
            0xffffffff00000000,
            0xfffffffffffffffe,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ],
        m0inv: 0x0000000100000001,
        rr: [
            0xfffffffe00000001,
            0x0000000200000000,
            0xfffffffe00000000,
            0x0000000200000000,
            0x0000000000000001,
            0x0000000000000000,
        ],
    },
    n: Modulus {
        m: [
            0xecec196accc52973,
            0x581a0db248b0a77a,
            0xc7634d81f4372ddf,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ],
        m0inv: 0x6ed46089e88fdc45,
        rr: [
            0x2d319b2419b409a9,
            0xff3d81e5df1aa419,
            0xbc3e483afcb82947,
            0xd40d49174aab1cc5,
            0x3fb05b7a28266895,
            0x0c84ee012b39bf21,
        ],
    },
    b: [
        0x2a85c8edd3ec2aef,
        0xc656398d8a2ed19d,
        0x0314088f5013875a,
        0x181d9c6efe814112,
        0x988e056be3f82d19,
        0xb3312fa7e23ee7e4,
    ],
    bytes: 48,
};

// G, 3G, 5G, ... as affine x and y in Montgomery form: 32 of them for
// P-256, whose u1 is in width-7 NAF, an addition per eight bits, and 8
// for P-384, width 5. registry/ecdsa/ecdsa-gen.py in rr's repository writes
// both, and the test constants recomputes them.

#[rustfmt::skip]
const P256_G: [[[u64; 4]; 2]; BASE_P256] = [
    [[0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510, 0x18905f76a53755c6],
     [0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325, 0x8571ff1825885d85]],
    [[0xffac3f904eebc127, 0xb027f84a087d81fb, 0x66ad77dd87cbbc98, 0x26936a3fb6ff747e],
     [0xb04c5c1fc983a7eb, 0x583e47ad0861fe1a, 0x788208311a2ee98e, 0xd5f06a29e587cc07]],
    [[0xbe1b8aaec45c61f5, 0x90ec649a94b9537d, 0x941cb5aad076c20c, 0xc9079605890523c8],
     [0xeb309b4ae7ba4f10, 0x73c568efe5eb882b, 0x3540a9877e7a1f68, 0x73a076bb2dd1e916]],
    [[0x0746354ea0173b4f, 0x2bd20213d23c00f7, 0xf43eaab50c23bb08, 0x13ba5119c3123e03],
     [0x2847d0303f5b9d4d, 0x6742f2f25da67bdd, 0xef933bdc77c94195, 0xeaedd9156e240867]],
    [[0x75c96e8f264e20e8, 0xabe6bfed59a7a841, 0x2cc09c0444c8eb00, 0xe05b3080f0c4e16b],
     [0x1eb7777aa45f3314, 0x56af7bedce5d45e3, 0x2b6e019a88b12f1a, 0x086659cdfd835f9b]],
    [[0xea7d260a6245e404, 0x9de407956e7fdfe0, 0x1ff3a4158dac1ab5, 0x3e7090f1649c9073],
     [0x1a7685612b944e88, 0x250f939ee57f61c8, 0x0c0daa891ead643d, 0x68930023e125b88e]],
    [[0xccc425634b2ed709, 0x0e356769856fd30d, 0xbcbcd43f559e9811, 0x738477ac5395b759],
     [0x35752b90c00ee17f, 0x68748390742ed2e3, 0x7cd06422bd1f5bc1, 0xfbc08769c9e7b797]],
    [[0x72bcd8b7bc60055b, 0x03cc23ee56e27e4b, 0xee337424e4819370, 0xe2aa0e430ad3da09],
     [0x40b8524f6383c45d, 0xd766355442a41b25, 0x64efa6de778a4797, 0x2042170a7079adf4]],
    [[0x97091dcbd53c5c9d, 0xf17624b6ac0a177b, 0xb0f139752cfe2dff, 0xc1a35c0a6c7a574e],
     [0x227d314693e79987, 0x0575bf30e89cb80e, 0x2f4e247f0d1883bb, 0xebd512263274c3d0]],
    [[0xfea912baa5659ae8, 0x68363aba25e1a16e, 0xb8842277752c41ac, 0xfe545c282897c3fc],
     [0x2d36e9e7dc4c696b, 0x5806244afba977c5, 0x85665e9be39508c1, 0xf720ee256d12597b]],
    [[0x562e4cecc135b208, 0x74e1b2654783f47d, 0x6d2a506c5a3f3b30, 0xecead9f4c16762fc],
     [0xf29dd4b2e286e5b9, 0x1b0fadc083bb3c61, 0x7a75023e7fac29a4, 0xc086d5f1c9477fa3]],
    [[0xf4f876532de45068, 0x37c7a7e89e2e1f6e, 0xd0825fa2a3584069, 0xaf2cea7c1727bf42],
     [0x0360a4fb9e4785a9, 0xe5fda49c27299f4a, 0x48068e1371ac2f71, 0x83d0687b9077666f]],
    [[0xa4a319acd837879f, 0x6fc1b49eed6b67b0, 0xe395993332f1f3af, 0x966742eb65432a2e],
     [0x4b8dc9feb4966228, 0x96cc631243f43950, 0x12068859c9b731ee, 0x7b948dc356f79968]],
    [[0x042c2af497e2feb4, 0xd36a42d7aebf7313, 0x49d2c9eb084ffdd7, 0x9f8aa54b2ef7c76a],
     [0x9200b7ba09895e70, 0x3bd0c66fddb7fb58, 0x2d97d10878eb4cbb, 0x2d431068d84bde31]],
    [[0x5e5db46acb66e132, 0xf1be963a0d925880, 0x944a70270317b9e2, 0xe266f95948603d48],
     [0x98db66735c208899, 0x90472447a2fb18a3, 0x8a966939777c619f, 0x3798142a2a3be21b]],
    [[0xe2f73c696755ff89, 0xdd3cf7e7473017e6, 0x8ef5689d3cf7600d, 0x948dc4f8b1fc87b4],
     [0xd9e9fe814ea53299, 0x2d921ca298eb6028, 0xfaecedfd0c9803fc, 0xf38ae8914d7b4745]],
    [[0x871514560f664534, 0x85ceae7c4b68f103, 0xac09c4ae65578ab9, 0x33ec6868f044b10c],
     [0x6ac4832b3a8ec1f1, 0x5509d1285847d5ef, 0xf909604f763f1574, 0xb16c4303c32f63c4]],
    [[0xfd16847fdec67ef5, 0x742ee464233e76b7, 0x0b8e4134efc2b4c8, 0xca640b8642a3e521],
     [0x653a01908ceb6aa9, 0x313c300c547852d5, 0x24e4ab126b237af7, 0x2ba901628bb47af8]],
    [[0x00467bc58cce08b5, 0xb636458c7f178d55, 0xc5748baea677d806, 0x2763a387dfa394eb],
     [0xa12b448a7d3cebb6, 0xe7adda3e6f20d850, 0xf63ebce51558462c, 0x58b36143620088a8]],
    [[0xa9d89488a059c142, 0x6f5ae714ff0b9346, 0x068f237d16fb3664, 0x5853e4c4363186ac],
     [0xe2d87d2363c52f98, 0x2ec4a76681828876, 0x47b864fae14e7b1c, 0x0c0bc0e569192408]],
    [[0x624d60492ed22e91, 0x6fdfe0b56f072822, 0xeeca111539ce2271, 0x98100a4fdb01614f],
     [0xb6b0daa2a35c628f, 0xb6f94d2ec87e9a47, 0xc67732591d57d9ce, 0xf70bfeec03884a7b]],
    [[0x4ff23ffd248a7d06, 0x80c5bfb4878873fa, 0xb7d9ad9005745981, 0x179c85db3db01994],
     [0xba41b06261a6966c, 0x4d82d052eadce5a8, 0x9e91cd3ba5e6a318, 0x47795f4f95b2dda0]],
    [[0x1ee426ccd5cd79bf, 0x0032940b946c6e18, 0x1b1e8ae057477f58, 0xe94f7d346d823278],
     [0xc747cb96782ba21a, 0xc5254469f72b33a5, 0x772ef6dec7f80c81, 0xd73acbfe2cd9e6b5]],
    [[0x283c7513caa76097, 0x0a624fa936c83906, 0x6b20afec715af2c7, 0x4b969974eba78bfd],
     [0x220755ccd921d60e, 0x9b944e107baeca13, 0x04819d515ded93d4, 0x9bbff86e6dddfd27]],
    [[0x21950b421ff6acd3, 0xffe7048453dc6909, 0xff4cd0b228766127, 0xabdbe6084fb7db2b],
     [0x837c92285e1109e8, 0x26147d27f4645b5a, 0x4d78f592f7818ed8, 0xd394077ef247fa36]],
    [[0x508cec1c3b3f64c9, 0xe20bc0ba1e5edf3f, 0xda1deb852f4318d4, 0xd20ebe0d5c3fa443],
     [0x370b4ea773241ea3, 0x61f1511c5e1a5f65, 0x99a5e23d82681c62, 0xd731e383a2f54c2d]],
    [[0x97359638546c4d8d, 0x5f9c3fc492f24679, 0x912e8beda8c8acd9, 0xec3a318d306634b0],
     [0x80167f41c31cb264, 0x3db82f6f522113f2, 0xb155bcd2dcafe197, 0xfba1da5943465283]],
    [[0x258bbbf9e7305683, 0x31eea5bf07ef5be6, 0x0deb0e4a46c814c1, 0x5cee8449a7b730dd],
     [0xeab495c5a0182bde, 0xee759f879e27a6b4, 0xc2cf6a6880e518ca, 0x25e8013ff14cf3f4]],
    [[0x3ec832e77acaca28, 0x1bfeea57c7385b29, 0x068212e3fd1eaf38, 0xc13298306acf8ccc],
     [0xb909f2db2aac9e59, 0x5748060db661782a, 0xc5ab2632c79b7a01, 0xda44c6c600017626]],
    [[0x69d44ed65c46aa8e, 0x2100d5d3a8d063d1, 0xcb9727eaa2d17c36, 0x4c2bab1b8add53b7],
     [0xa084e90c15426704, 0x778afcd3a837ebea, 0x6651f7017ce477f8, 0xa062499846fb7a8b]],
    [[0x3667eb1a7f4c04cc, 0x59556621a9404f84, 0x71cdf6537eceb50a, 0x994a44a69b8335fa],
     [0xd7faf819dbeb9b69, 0x473c5680eed4350d, 0xb6658466da44bba2, 0x0d1bc780872bdbf3]],
    [[0xb8d3d9319ff91fe5, 0x039c4800f0518eed, 0x95c376329182cb26, 0x0763a43482fc568d],
     [0x707c04d5383e76ba, 0xac98b930824e8197, 0x92bf7c8f91230de0, 0x90876a0140959b70]],
];

#[rustfmt::skip]
const P384_G: [[[u64; 6]; 2]; TABLE] = [
    [[0x3dd0756649c0b528, 0x20e378e2a0d6ce38, 0x879c3afc541b4d6e, 0x6454868459a30eff, 0x812ff723614ede2b, 0x4d3aadc2299e1513],
     [0x23043dad4b03a4fe, 0xa1bfa8bf7bb4a9ac, 0x8bade7562e83b050, 0xc6c3521968f4ffd9, 0xdd8002263969a840, 0x2b78abc25a15c5e9]],
    [[0x05e4dbe6c1dc4073, 0xc54ea9fff04f779c, 0x6b2034e9a170ccf0, 0x3a48d732d51c6c3e, 0xe36f7e2d263aa470, 0xd283fe68e7c1c3ac],
     [0x7e284821c04ee157, 0x92d789a77ae0e36d, 0x132663c04ef67446, 0x68012d5ad2e1d0b4, 0xf6db68b15102b339, 0x465465fc983292af]],
    [[0xbb595eba68f1f0df, 0xc185c0cbcc873466, 0x7f1eb1b5293c703b, 0x60db2cf5aacc05e6, 0xc676b987e2e8e4c6, 0xe1bb26b11d178ffb],
     [0x2b694ba07073fa21, 0x22c16e2e72f34566, 0x80b61b3101c35b99, 0x4b237faf982c0411, 0xe6c5944024de236d, 0x4db1c9d6e209e4a3]],
    [[0xdf13b9d17d69222b, 0x4ce6415f874774b1, 0x731edcf8211faa95, 0x5f4215d1659753ed, 0xf893db589db2df55, 0x932c9f811c89025b],
     [0x0996b2207706a61e, 0x135349d5a8641c79, 0x65aad76f50130844, 0x0ff37c0401fff780, 0xf57f238e693b0706, 0xd90a16b6af6c9b3e]],
    [[0x2f5d200e2353b92f, 0xe35d87293fd7e4f9, 0x26094833a96d745d, 0xdc351dc13cbfff3f, 0x26d464c6dad54d6a, 0x5cab1d1d53636c6a],
     [0xf2813072b18ec0b0, 0x3777e270d742aa2f, 0x27f061c7033ca7c2, 0xa6ecaccc68ead0d8, 0x7d9429f4ee69a754, 0xe770633431e8f5c6]],
    [[0xc7708b19b68b8c7d, 0x4532077c44377aba, 0x0dcc67706cdad64f, 0x01b8bf56147b6602, 0xf8d89885f0561d79, 0x9c19e9fc7ba9c437],
     [0x764eb146bdc4ba25, 0x604fe46bac144b83, 0x3ce813298a77e780, 0x2e070f36fe9e682e, 0x41821d0c3a53287a, 0x9aa62f9f3533f918]],
    [[0x9b7aeb7e75ccbdfb, 0xb25e28c5f6749a95, 0x8a7a8e4633b7d4ae, 0xdb5203a8d9c1bd56, 0xd2657265ed22df97, 0xb51c56e18cf23c94],
     [0xf4d394596c3d812d, 0xd8e88f1a87cae0c2, 0x789a2a48cf4d0fe3, 0xb7feac2dfec38d60, 0x81fdbd1c3b490ec3, 0x4617adb7cc6979e1]],
    [[0x446ad8884709f4a9, 0x2b7210e2ec3dabd8, 0x83ccf19550e07b34, 0x59500917789b3075, 0x0fc01fd4eb085993, 0xfb62d26f4903026b],
     [0x2309cc9d6fe989bb, 0x61609cbd144bd586, 0x4b23d3a0de06610c, 0xdddc2866d898f470, 0x8733fc41400c5797, 0x5a68c6fed0bc2716]],
];

impl Curve {
    fn params(&self) -> &'static Params {
        match self {
            Curve::P256 => &P256,
            Curve::P384 => &P384,
        }
    }
}

/// Whether signature, DER's Ecdsa-Sig-Value, signs hash under public,
/// an uncompressed point 04 || X || Y. The hash is cut to the order's
/// bits when longer (SEC 1 4.1.4 step 5), and may be of any length.
pub fn verify(curve: &Curve, public: &[u8], hash: &[u8], signature: &[u8]) -> bool {
    let params = curve.params();
    let Some((r, s)) = parse(signature, params.bytes) else {
        return false;
    };
    let (Some(r), Some(s)) = (scalar(curve, r), scalar(curve, s)) else {
        return false;
    };
    let Some(q) = public_point(curve, public) else {
        return false;
    };
    let e = truncated(curve, hash);
    // w = s^-1; u1 = e w and u2 = r w, all mod n. w goes into Montgomery
    // form, so each product with a plain number comes out plain.
    let w = nmul(curve, &invert_scalar(curve, &s), &params.n.rr);
    let u1 = nmul(curve, &e, &w);
    let u2 = nmul(curve, &r, &w);
    let mut sum = infinity();
    combine(curve, &u1, &q, &u2, &mut sum);
    if is_zero(&sum.z) {
        return false;
    }
    x_matches(curve, &sum, &r)
}

/// r and s from DER's SEQUENCE of two INTEGERs, without their sign
/// byte; None unless the encoding is DER's one encoding of them (X.690
/// 8.3 and 10.1), each at most bytes long, with nothing after.
fn parse(signature: &[u8], bytes: usize) -> Option<(&[u8], &[u8])> {
    let body = element(signature, 0x30)?;
    if body.len() + 2 != signature.len() {
        return None;
    }
    let r = element(body, 0x02)?;
    let rest = body.get(r.len() + 2..)?;
    let s = element(rest, 0x02)?;
    if s.len() + 2 != rest.len() {
        return None;
    }
    Some((positive(r, bytes)?, positive(s, bytes)?))
}

/// The contents of the element of tag at the start of input. Contents
/// of these two curves are under 128 bytes, so the length is one byte:
/// a long form would be either not minimal or too long.
fn element(input: &[u8], tag: u8) -> Option<&[u8]> {
    let [found, length, rest @ ..] = input else {
        return None;
    };
    if *found != tag || *length >= 0x80 {
        return None;
    }
    rest.get(..usize::from(*length))
}

/// A positive INTEGER's magnitude, at most bytes long: no sign bit set,
/// and a leading zero only where the next byte's top bit needs it.
fn positive(contents: &[u8], bytes: usize) -> Option<&[u8]> {
    let magnitude = match contents {
        [] => return None,
        [first, ..] if *first >= 0x80 => return None,
        [0, next, ..] if *next < 0x80 => return None,
        [0, rest @ ..] if !rest.is_empty() => rest,
        [..] => contents,
    };
    if magnitude.len() > bytes {
        return None;
    }
    Some(magnitude)
}

/// A scalar of the signature as a number in [1, n - 1].
fn scalar(curve: &Curve, bytes: &[u8]) -> Option<Fe> {
    let value = load(bytes)?;
    let (_, below) = sub_limbs(&value, &curve.params().n.m);
    if is_zero(&value) || !below {
        return None;
    }
    Some(value)
}

/// The public key as a point in Montgomery form: 04 || X || Y with X and
/// Y below p and on the curve. Infinity has no such encoding.
fn public_point(curve: &Curve, public: &[u8]) -> Option<Affine> {
    let params = curve.params();
    let ([4], coordinates) = public.split_at_checked(1)? else {
        return None;
    };
    let (x, y) = coordinates.split_at_checked(params.bytes)?;
    if y.len() != params.bytes {
        return None;
    }
    let (x, y) = (load(x)?, load(y)?);
    let (_, x_below) = sub_limbs(&x, &params.p.m);
    let (_, y_below) = sub_limbs(&y, &params.p.m);
    if !x_below || !y_below {
        return None;
    }
    let x = fmul(curve, &x, &params.p.rr);
    let y = fmul(curve, &y, &params.p.rr);
    // y^2 = x^3 - 3x + b.
    let b = fmul(curve, &params.b, &params.p.rr);
    let x3 = fmul(curve, &fsqr(curve, &x), &x);
    let three_x = fadd(curve, &fadd(curve, &x, &x), &x);
    let right = fadd(curve, &fsub(curve, &x3, &three_x), &b);
    if fsqr(curve, &y) != right {
        return None;
    }
    Some(Affine { x, y })
}

/// The hash as a number mod n: its leftmost bits, as many as n has. Both
/// orders fill whole bytes, so the cut is at a byte.
fn truncated(curve: &Curve, hash: &[u8]) -> Fe {
    let params = curve.params();
    let hash = hash.get(..params.bytes).unwrap_or(hash);
    let mut e = [0; LIMBS];
    for (limb, chunk) in e.iter_mut().zip(hash.rchunks(8)) {
        *limb = chunk
            .iter()
            .fold(0, |acc, byte| (acc << 8) | u64::from(*byte));
    }
    // e < 2^bits < 2n: one subtraction reduces it.
    let (reduced, below) = sub_limbs(&e, &params.n.m);
    if below { e } else { reduced }
}

/// Big-endian bytes as limbs; None past 48 bytes.
fn load(bytes: &[u8]) -> Option<Fe> {
    if bytes.len() > 8 * LIMBS {
        return None;
    }
    let mut value = [0; LIMBS];
    for (limb, chunk) in value.iter_mut().zip(bytes.rchunks(8)) {
        *limb = chunk
            .iter()
            .fold(0, |acc, byte| (acc << 8) | u64::from(*byte));
    }
    Some(value)
}

/// Whether the affine x of point, reduced mod n, is r. x = X / Z^2, so
/// this compares X with r Z^2, and with (r + n) Z^2 when r + n < p,
/// sparing the inversion of Z.
fn x_matches(curve: &Curve, point: &Point, r: &Fe) -> bool {
    let params = curve.params();
    let zz = fsqr(curve, &point.z);
    let candidate = fmul(curve, &fmul(curve, r, &params.p.rr), &zz);
    if candidate == point.x {
        return true;
    }
    let (wide, carry) = add_limbs(r, &params.n.m);
    let (_, below) = sub_limbs(&wide, &params.p.m);
    if carry || !below {
        return false;
    }
    fmul(curve, &fmul(curve, &wide, &params.p.rr), &zz) == point.x
}

/// k1 G + k2 q into acc: both scalars in NAF, one doubling per bit for
/// both and an addition per nonzero digit of either. q's is width 5,
/// from 8 odd multiples; G's are constants, affine, whose additions
/// cost less, and enough on P-256 for width 7. The points are built in
/// place: a point is 144 bytes, which x86-64 copies by a call to memcpy.
fn combine(curve: &Curve, k1: &Fe, q: &Affine, k2: &Fe, acc: &mut Point) {
    let mut table = [const { infinity() }; TABLE];
    odd_multiples(curve, q, &mut table);
    let width = match curve {
        Curve::P256 => 7,
        Curve::P384 => 5,
    };
    let (mut d1, mut d2) = ([0; DIGITS], [0; DIGITS]);
    naf(k1, width, &mut d1);
    naf(k2, 5, &mut d2);
    *acc = infinity();
    for (g_digit, q_digit) in d1.iter().zip(&d2).rev() {
        double(curve, acc);
        if *g_digit != 0 {
            let entry = base_multiple(curve, *g_digit);
            add_affine(curve, acc, &entry);
        }
        if *q_digit != 0 {
            add_digit(curve, acc, &table, *q_digit);
        }
    }
}

/// digit times G, affine, from the constant table.
fn base_multiple(curve: &Curve, digit: i8) -> Affine {
    let index = usize::from(digit.unsigned_abs() >> 1);
    let mut entry = Affine {
        x: [0; LIMBS],
        y: [0; LIMBS],
    };
    let coordinates: (&[u64], &[u64]) = match curve {
        // rr: escape(panic): naf's digits for G are odd and in [-63, 63]
        // on P-256, [-15, 15] on P-384, so half the magnitude is below
        // the table's length.
        Curve::P256 => (&P256_G[index][0], &P256_G[index][1]),
        // rr: escape(panic): as above.
        Curve::P384 => (&P384_G[index][0], &P384_G[index][1]),
    };
    for (limb, word) in entry.x.iter_mut().zip(coordinates.0) {
        *limb = *word;
    }
    for (limb, word) in entry.y.iter_mut().zip(coordinates.1) {
        *limb = *word;
    }
    if digit < 0 {
        entry.y = fsub(curve, &[0; LIMBS], &entry.y);
    }
    entry
}

/// Adds to acc digit times the point whose odd multiples table holds.
fn add_digit(curve: &Curve, acc: &mut Point, table: &[Point; TABLE], digit: i8) {
    // rr: escape(panic): as in base_multiple.
    let entry = &table[usize::from(digit.unsigned_abs() >> 1)];
    if digit > 0 {
        add(curve, acc, entry);
        return;
    }
    let negated = Point {
        x: entry.x,
        y: fsub(curve, &[0; LIMBS], &entry.y),
        z: entry.z,
    };
    add(curve, acc, &negated);
}

/// P, 3P, ..., 15P into table: P, then each the one before it plus 2P.
/// Points are written a coordinate at a time, as add writes them.
fn odd_multiples(curve: &Curve, p: &Affine, table: &mut [Point; TABLE]) {
    let mut twice = infinity();
    add_affine(curve, &mut twice, p);
    double(curve, &mut twice);
    let [first, rest @ ..] = table;
    add_affine(curve, first, p);
    let mut before: &Point = first;
    for slot in rest {
        slot.x = before.x;
        slot.y = before.y;
        slot.z = before.z;
        add(curve, slot, &twice);
        before = slot;
    }
}

/// The NAF of k of a width up to 7, least significant digit first: each
/// digit 0 or odd and below 2^(width - 1) in magnitude, and of any width
/// in a row at most one is nonzero.
fn naf(k: &Fe, width: u32, digits: &mut [i8; DIGITS]) {
    // One limb more: rounding a digit up may carry past k's top.
    let mut rest = [0_u64; LIMBS + 1];
    for (limb, word) in rest.iter_mut().zip(k) {
        *limb = *word;
    }
    let size = 1 << width;
    digits.fill(0);
    for digit in digits.iter_mut() {
        let low = rest[0] & (size - 1);
        if low & 1 == 1 {
            if low < size / 2 {
                // rr: escape(cast): low is below 2^(width - 1), at most 64.
                *digit = low as i8;
                rest[0] -= low;
            } else {
                // rr: escape(cast): size - low is at most 2^(width - 1).
                *digit = -((size - low) as i8);
                let mut carry = size - low;
                for limb in &mut rest {
                    let (sum, over) = limb.overflowing_add(carry);
                    *limb = sum;
                    carry = u64::from(over);
                }
            }
        }
        let mut high = 0_u64;
        for limb in rest.iter_mut().rev() {
            let next = *limb << 63;
            *limb = (*limb >> 1) | high;
            high = next;
        }
    }
}

const fn infinity() -> Point {
    Point {
        x: [0; LIMBS],
        y: [0; LIMBS],
        z: [0; LIMBS],
    }
}

/// a doubled in place, by dbl-2001-b for a = -3.
fn double(curve: &Curve, a: &mut Point) {
    if is_zero(&a.z) || is_zero(&a.y) {
        *a = infinity();
        return;
    }
    let delta = fsqr(curve, &a.z);
    let gamma = fsqr(curve, &a.y);
    let beta = fmul(curve, &a.x, &gamma);
    let product = fmul(
        curve,
        &fsub(curve, &a.x, &delta),
        &fadd(curve, &a.x, &delta),
    );
    let alpha = fadd(curve, &fadd(curve, &product, &product), &product);
    let beta2 = fadd(curve, &beta, &beta);
    let beta4 = fadd(curve, &beta2, &beta2);
    let beta8 = fadd(curve, &beta4, &beta4);
    let x = fsub(curve, &fsqr(curve, &alpha), &beta8);
    let yz = fadd(curve, &a.y, &a.z);
    let z = fsub(curve, &fsub(curve, &fsqr(curve, &yz), &gamma), &delta);
    let gamma2 = fsqr(curve, &gamma);
    let gamma4 = fadd(curve, &gamma2, &gamma2);
    let gamma8 = fadd(curve, &gamma4, &gamma4);
    let gamma16 = fadd(curve, &gamma8, &gamma8);
    let y = fsub(
        curve,
        &fmul(curve, &alpha, &fsub(curve, &beta4, &x)),
        &gamma16,
    );
    // Each coordinate on its own: a Point built whole goes through a
    // copy of all 144 bytes, a call to memcpy on x86-64.
    a.x = x;
    a.y = y;
    a.z = z;
}

/// b added to a in place, by add-2007-bl, with the cases it leaves
/// out: infinity on either side, a = b and a = -b.
fn add(curve: &Curve, a: &mut Point, b: &Point) {
    if is_zero(&a.z) {
        a.x = b.x;
        a.y = b.y;
        a.z = b.z;
        return;
    }
    if is_zero(&b.z) {
        return;
    }
    let z1z1 = fsqr(curve, &a.z);
    let z2z2 = fsqr(curve, &b.z);
    let u1 = fmul(curve, &a.x, &z2z2);
    let u2 = fmul(curve, &b.x, &z1z1);
    let s1 = fmul(curve, &fmul(curve, &a.y, &b.z), &z2z2);
    let s2 = fmul(curve, &fmul(curve, &b.y, &a.z), &z1z1);
    let h = fsub(curve, &u2, &u1);
    let r = fsub(curve, &s2, &s1);
    if is_zero(&h) {
        if is_zero(&r) {
            double(curve, a);
        } else {
            *a = infinity();
        }
        return;
    }
    let r = fadd(curve, &r, &r);
    let h2 = fadd(curve, &h, &h);
    let i = fsqr(curve, &h2);
    let j = fmul(curve, &h, &i);
    let v = fmul(curve, &u1, &i);
    let x = fsub(
        curve,
        &fsub(curve, &fsub(curve, &fsqr(curve, &r), &j), &v),
        &v,
    );
    let s1j = fmul(curve, &s1, &j);
    let y = fsub(
        curve,
        &fmul(curve, &r, &fsub(curve, &v, &x)),
        &fadd(curve, &s1j, &s1j),
    );
    let zs = fadd(curve, &a.z, &b.z);
    let zz = fsub(curve, &fsub(curve, &fsqr(curve, &zs), &z1z1), &z2z2);
    let z = fmul(curve, &zz, &h);
    // Each coordinate on its own: a Point built whole goes through a
    // copy of all 144 bytes, a call to memcpy on x86-64.
    a.x = x;
    a.y = y;
    a.z = z;
}

/// An affine b added to a in place, by madd-2007-bl, with the cases
/// it leaves out as add has them.
fn add_affine(curve: &Curve, a: &mut Point, b: &Affine) {
    if is_zero(&a.z) {
        a.x = b.x;
        a.y = b.y;
        a.z = one(curve);
        return;
    }
    let z1z1 = fsqr(curve, &a.z);
    let u2 = fmul(curve, &b.x, &z1z1);
    let s2 = fmul(curve, &fmul(curve, &b.y, &a.z), &z1z1);
    let h = fsub(curve, &u2, &a.x);
    let r = fsub(curve, &s2, &a.y);
    if is_zero(&h) {
        if is_zero(&r) {
            double(curve, a);
        } else {
            *a = infinity();
        }
        return;
    }
    let hh = fsqr(curve, &h);
    let hh2 = fadd(curve, &hh, &hh);
    let i = fadd(curve, &hh2, &hh2);
    let j = fmul(curve, &h, &i);
    let r = fadd(curve, &r, &r);
    let v = fmul(curve, &a.x, &i);
    let x = fsub(
        curve,
        &fsub(curve, &fsub(curve, &fsqr(curve, &r), &j), &v),
        &v,
    );
    let y1j = fmul(curve, &a.y, &j);
    let y = fsub(
        curve,
        &fmul(curve, &r, &fsub(curve, &v, &x)),
        &fadd(curve, &y1j, &y1j),
    );
    let zh = fadd(curve, &a.z, &h);
    let z = fsub(curve, &fsub(curve, &fsqr(curve, &zh), &z1z1), &hh);
    // Each coordinate on its own: a Point built whole goes through a
    // copy of all 144 bytes, a call to memcpy on x86-64.
    a.x = x;
    a.y = y;
    a.z = z;
}

/// s^-1 mod n for s in [1, n - 1], plain.
fn invert_scalar(curve: &Curve, s: &Fe) -> Fe {
    match curve {
        Curve::P256 => invert(&P256.n.m[..4], P256.n.m0inv, s),
        Curve::P384 => invert(&P384.n.m, P384.n.m0inv, s),
    }
}

/// a^-1 mod m for a in [1, m - 1] and m an odd prime, by the binary
/// extended Euclidean algorithm. It keeps x1 a = u and x2 a = v (mod
/// m), u and v odd, from u = a and v = m; each round takes the smaller
/// from the larger, which halves at least once, until u = v = 1. Not
/// constant time, which public scalars do not need: about half the time
/// of the Fermat power a^(m - 2).
#[inline(always)]
fn invert(m: &[u64], m0inv: u64, a: &Fe) -> Fe {
    let mut u = *a;
    let mut v = [0; LIMBS];
    for (limb, word) in v.iter_mut().zip(m) {
        *limb = *word;
    }
    let mut x1 = [0; LIMBS];
    x1[0] = 1;
    let mut x2 = [0; LIMBS];
    let limbs = m.len();
    halve(m, m0inv, &mut u, &mut x1);
    // Each round takes a bit off u or v at least: their bits bound it.
    for _ in 0..2 * 64 * LIMBS {
        let (difference, below) = sub_limbs(&u, &v);
        if is_zero(&difference) {
            break;
        }
        if below {
            v = sub_limbs(&v, &u).0;
            // rr: escape(panic): m has at most LIMBS limbs.
            x2 = sub_mod(m, &x2[..limbs], &x1[..limbs]);
            halve(m, m0inv, &mut v, &mut x2);
        } else {
            u = difference;
            // rr: escape(panic): as above.
            x1 = sub_mod(m, &x1[..limbs], &x2[..limbs]);
            halve(m, m0inv, &mut u, &mut x1);
        }
    }
    x1
}

/// Divides w, nonzero, by its largest power of two, and x by the same
/// mod m: x + c m with c = -x m^-1 mod 2^k is a multiple of 2^k, and
/// below 2m once divided. k is at most 63 a step.
#[inline(always)]
fn halve(m: &[u64], m0inv: u64, w: &mut Fe, x: &mut Fe) {
    for _ in 0..=LIMBS * 64 / 63 {
        let zeros = trailing_zeros(w).min(63);
        if zeros == 0 {
            return;
        }
        shift_right(w, 0, zeros);
        let c = x[0].wrapping_mul(m0inv) & ((1 << zeros) - 1);
        let mut carry = 0;
        for (limb, y) in x.iter_mut().zip(m) {
            (*limb, carry) = mac(c, *y, *limb, carry);
        }
        // The carry is the word above m's limbs.
        match x.get_mut(m.len()) {
            Some(limb) => {
                *limb = carry;
                shift_right(x, 0, zeros);
            }
            None => shift_right(x, carry, zeros),
        }
        let (reduced, below) = sub_limbs(x, m);
        if !below {
            *x = reduced;
        }
    }
}

/// The trailing zero bits of w, nonzero.
fn trailing_zeros(w: &Fe) -> u32 {
    let mut zeros = 0;
    for limb in w {
        if *limb != 0 {
            return zeros + limb.trailing_zeros();
        }
        zeros += 64;
    }
    zeros
}

/// w = (w + top 2^(64 LIMBS)) / 2^k, for k in 1..64 and w + top 2^(64
/// LIMBS) a multiple of 2^k.
fn shift_right(w: &mut Fe, top: u64, k: u32) {
    let mut above = top;
    for limb in w.iter_mut().rev() {
        let pair = (u128::from(above) << 64) | u128::from(*limb);
        above = *limb;
        // rr: escape(cast): the low word of the pair shifted by under 64.
        *limb = (pair >> k) as u64;
    }
}

fn is_zero(a: &Fe) -> bool {
    a.iter().all(|limb| *limb == 0)
}

/// One in Montgomery form: R mod p.
fn one(curve: &Curve) -> Fe {
    let mut one = [0; LIMBS];
    one[0] = 1;
    fmul(curve, &one, &curve.params().p.rr)
}

// Each operation below picks its curve's modulus as a constant, so the
// compiler unrolls the limbs and folds the modulus into the code.

/// a b / R mod p.
#[inline(always)]
fn fmul(curve: &Curve, a: &Fe, b: &Fe) -> Fe {
    match curve {
        Curve::P256 => reduce_p256(&product(&a[..4], &b[..4])),
        Curve::P384 => reduce(&P384.p.m, P384.p.m0inv, product(a, b)),
    }
}

/// a^2 / R mod p.
#[inline(always)]
fn fsqr(curve: &Curve, a: &Fe) -> Fe {
    match curve {
        Curve::P256 => reduce_p256(&square(&a[..4])),
        Curve::P384 => reduce(&P384.p.m, P384.p.m0inv, square(a)),
    }
}

/// a b / R mod n.
#[inline(always)]
fn nmul(curve: &Curve, a: &Fe, b: &Fe) -> Fe {
    match curve {
        Curve::P256 => reduce(&P256.n.m[..4], P256.n.m0inv, product(&a[..4], &b[..4])),
        Curve::P384 => reduce(&P384.n.m, P384.n.m0inv, product(a, b)),
    }
}

/// a + b mod p, for a and b below p.
#[inline(always)]
fn fadd(curve: &Curve, a: &Fe, b: &Fe) -> Fe {
    match curve {
        Curve::P256 => add_mod(&P256.p.m[..4], &a[..4], &b[..4]),
        Curve::P384 => add_mod(&P384.p.m, a, b),
    }
}

/// a - b mod p, for a and b below p.
#[inline(always)]
fn fsub(curve: &Curve, a: &Fe, b: &Fe) -> Fe {
    match curve {
        Curve::P256 => sub_mod(&P256.p.m[..4], &a[..4], &b[..4]),
        Curve::P384 => sub_mod(&P384.p.m, a, b),
    }
}

// The limb arithmetic below wraps instead of checking: each product and
// sum is bounded in its comment, and an overflow check on each would
// cost the verification a large part of its time.

/// a b + c + d as low and high words: at most (2^64 - 1)^2 + 2 (2^64 -
/// 1) = 2^128 - 1, so it never wraps.
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let wide = u128::from(a)
        .wrapping_mul(u128::from(b))
        .wrapping_add(u128::from(c))
        .wrapping_add(u128::from(d));
    // rr: escape(cast): the two halves of the 128-bit sum.
    (wide as u64, (wide >> 64) as u64)
}

/// a b, for a and b of the same number of limbs: products independent
/// of each other, which the processor overlaps.
#[inline(always)]
fn product(a: &[u64], b: &[u64]) -> [u64; 2 * LIMBS] {
    let n = b.len();
    let mut t = [0_u64; 2 * LIMBS];
    for (i, x) in a.iter().enumerate() {
        // rr: escape(panic): i < n, and t holds 2n words.
        let row = &mut t[i..];
        let mut carry = 0;
        for (limb, y) in row.iter_mut().zip(b) {
            (*limb, carry) = mac(*x, *y, *limb, carry);
        }
        // rr: escape(panic): i + n < 2n.
        row[n] = carry;
    }
    t
}

/// a^2, each product of two limbs taken once and doubled.
#[inline(always)]
fn square(a: &[u64]) -> [u64; 2 * LIMBS] {
    let n = a.len();
    let mut t = [0_u64; 2 * LIMBS];
    for (i, x) in a.iter().enumerate() {
        // rr: escape(panic): i < n, and t holds 2n words.
        let row = &mut t[2 * i + 1..];
        let mut carry = 0;
        // rr: escape(panic): as above.
        for (limb, y) in row.iter_mut().zip(&a[i + 1..]) {
            (*limb, carry) = mac(*x, *y, *limb, carry);
        }
        // rr: escape(panic): the row ends at word i + n < 2n.
        row[n - i - 1] = carry;
    }
    // Twice the products above the diagonal, plus the squares on it.
    let mut high = 0;
    for word in &mut t {
        let next = *word >> 63;
        *word = (*word << 1) | high;
        high = next;
    }
    let mut carry = 0;
    for (pair, x) in t.as_chunks_mut::<2>().0.iter_mut().zip(a) {
        let [low, top] = pair;
        let (square, spill) = mac(*x, *x, *low, carry);
        *low = square;
        let (sum, over) = top.overflowing_add(spill);
        *top = sum;
        carry = u64::from(over);
    }
    t
}

/// reduce for P-256's p = 2^256 - 2^224 + 2^192 + 2^96 - 1, whose
/// -p^-1 mod 2^64 is 1: each round's u is the low word, and u p is
/// shifts of u but for the top word's product. The rounds depend on
/// each other, so this shortens the multiplication's longest path.
#[inline(always)]
fn reduce_p256(t: &[u64; 2 * LIMBS]) -> Fe {
    let [t0, t1, t2, t3, t4, t5, t6, t7, ..] = *t;
    let ([t1, t2, t3, t4], over) = round_p256([t0, t1, t2, t3, t4], false);
    let ([t2, t3, t4, t5], over) = round_p256([t1, t2, t3, t4, t5], over);
    let ([t3, t4, t5, t6], over) = round_p256([t2, t3, t4, t5, t6], over);
    let ([t4, t5, t6, t7], over) = round_p256([t3, t4, t5, t6, t7], over);
    let r = [t4, t5, t6, t7, 0, 0];
    let (reduced, below) = sub_limbs(&r, &P256.p.m[..4]);
    if over || !below { reduced } else { r }
}

/// One round of reduce_p256 on five words, low first: adds u p, with u
/// the low word, which clears it. over is the carry due in the top word.
#[inline(always)]
fn round_p256(words: [u64; 5], over: bool) -> ([u64; 4], bool) {
    let [u, w1, w2, w3, w4] = words;
    // u + u (2^64 - 1) is u 2^64, and with it w1 + u (2^32 - 1) + u is
    // w1 + u 2^32, whose high word is at most 2^32.
    let (s1, c1) = w1.overflowing_add(u << 32);
    let (s2, c2) = w2.overflowing_add((u >> 32) + u64::from(c1));
    let (s3, c3) = mac(u, P256.p.m[3], w3, u64::from(c2));
    let (s4, o1) = w4.overflowing_add(c3);
    let (s4, o2) = s4.overflowing_add(u64::from(over));
    ([s1, s2, s3, s4], o1 | o2)
}

/// t / 2^(64 n) mod m for t below m 2^(64 n): n rounds that each add the
/// multiple of m that clears the lowest word. The result is below 2m,
/// so one subtraction brings it below m.
#[inline(always)]
fn reduce(m: &[u64], m0inv: u64, mut t: [u64; 2 * LIMBS]) -> Fe {
    let n = m.len();
    let mut over = false;
    for i in 0..n {
        // rr: escape(panic): i < n, and t holds 2n words.
        let row = &mut t[i..];
        // rr: escape(panic): as above.
        let u = row[0].wrapping_mul(m0inv);
        let mut carry = 0;
        for (limb, y) in row.iter_mut().zip(m) {
            (*limb, carry) = mac(u, *y, *limb, carry);
        }
        // The carry out of this word is due in the next round's top one.
        // rr: escape(panic): i + n < 2n.
        let (sum, o1) = row[n].overflowing_add(carry);
        let (sum, o2) = sum.overflowing_add(u64::from(over));
        // rr: escape(panic): as above.
        row[n] = sum;
        over = o1 | o2;
    }
    let mut r = [0; LIMBS];
    // rr: escape(panic): n < 2n.
    for (limb, word) in r.iter_mut().zip(&t[n..2 * n]) {
        *limb = *word;
    }
    let (reduced, below) = sub_limbs(&r, m);
    if over || !below { reduced } else { r }
}

/// a + b and whether it carried out, over b's limbs.
#[inline(always)]
fn add_limbs(a: &[u64], b: &[u64]) -> (Fe, bool) {
    let mut sum = [0; LIMBS];
    let mut carry = false;
    for ((out, x), y) in sum.iter_mut().zip(a).zip(b) {
        let (s, c1) = x.overflowing_add(*y);
        let (s, c2) = s.overflowing_add(u64::from(carry));
        *out = s;
        carry = c1 | c2;
    }
    (sum, carry)
}

/// a - b over b's limbs, and whether a < b, which wraps it.
#[inline(always)]
fn sub_limbs(a: &[u64], b: &[u64]) -> (Fe, bool) {
    let mut difference = [0; LIMBS];
    let mut borrow = false;
    for ((out, x), y) in difference.iter_mut().zip(a).zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        *out = d;
        borrow = b1 | b2;
    }
    (difference, borrow)
}

#[inline(always)]
fn add_mod(m: &[u64], a: &[u64], b: &[u64]) -> Fe {
    let (sum, carry) = add_limbs(a, b);
    let (reduced, below) = sub_limbs(&sum, m);
    if carry || !below { reduced } else { sum }
}

#[inline(always)]
fn sub_mod(m: &[u64], a: &[u64], b: &[u64]) -> Fe {
    let (difference, borrow) = sub_limbs(a, b);
    if borrow {
        add_limbs(&difference, m).0
    } else {
        difference
    }
}

/// Any bytes as a curve, a key, a hash and a signature: verify answers
/// without a panic, and a signature parse accepts is the DER encoding of
/// what it read.
#[cfg(fuzzing)]
pub fn fuzz_verify(input: &[u8]) {
    let Some((&choice, rest)) = input.split_first() else {
        return;
    };
    let curve = if choice & 1 == 0 {
        Curve::P256
    } else {
        Curve::P384
    };
    let split = usize::from(choice >> 1).min(rest.len());
    let (hash, rest) = rest.split_at(split);
    let half = rest.len() / 2;
    let (public, signature) = rest.split_at(half);
    verify(&curve, public, hash, signature);
    verify(&curve, &[], hash, rest);
    if let Some((r, s)) = parse(rest, curve.params().bytes) {
        let mut encoded = alloc::vec::Vec::new();
        for integer in [r, s] {
            let sign = integer.first().is_some_and(|byte| *byte >= 0x80);
            encoded.push(2);
            encoded.push(u8::try_from(integer.len() + usize::from(sign)).unwrap());
            if sign {
                encoded.push(0);
            }
            encoded.extend_from_slice(integer);
        }
        let body = u8::try_from(encoded.len()).unwrap();
        assert_eq!(rest.get(..2), Some(&[0x30, body][..]));
        assert_eq!(rest.get(2..), Some(&encoded[..]));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BASE_P256, Curve, Fe, LIMBS, P256, P384, TABLE, add, add_affine, add_mod, base_multiple,
        combine, double, fmul, fsqr, infinity, invert_scalar, is_zero, nmul, product, public_point,
        reduce, reduce_p256, sub_limbs, verify,
    };
    use alloc::vec::Vec;
    use test::Bencher;

    fn hex(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut high = None;
        for c in text.bytes() {
            let digit = u8::try_from(char::from(c).to_digit(16).unwrap()).unwrap();
            match high.take() {
                None => high = Some(digit),
                Some(first) => bytes.push((first << 4) | digit),
            }
        }
        bytes
    }

    /// Wycheproof's P-256 key of its first ECDSA cases, and its first
    /// signature: SHA-256 of the empty message.
    const KEY256: &str = "0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5\
                          87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d";
    const EMPTY256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SIG256: &str = "3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d877\
                          0b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2";

    /// Wycheproof's cases (C2SP/wycheproof testvectors_v1), each named
    /// by file and tcId; the hash is that of the case's message.
    #[test]
    fn wycheproof() {
        let key384 = "0429bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61\
                      ef182e155a54345a5e8e5e88f064e5bc9a525ab7f764dad3dae1468c2b419f3b62b9\
                      ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3";
        let large256 = "040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103\
                        c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        let large384 = "044bf4e52f958427ebb5915fb8c9595551b4d3a3fdab67badd9d6c3093f425ba43\
                        630df71f42f0eb7ceaa94d9f6448a85dd30331588249fd2fdc0b309ec7ed8481bc16\
                        f27800c13d7db700fc82e1b1c8545aa0c0d3b56e3bfe789fc18a916887c2";
        let hash_large256 = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
        let hash_large384 = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d3817\
                             9023942871acb7002dfafdfffc8deace";
        for (curve, key, hash, signature, valid) in [
            // secp256r1_sha256 1.
            (Curve::P256, KEY256, EMPTY256, SIG256, true),
            // secp256r1_sha512 1: a 64-byte hash, cut to 32.
            (
                Curve::P256,
                KEY256,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "30440220093f3825c0cf820cced816a3a67446c85606a6d529e43857643fccc11e1f\
                 705f0220769782888c63058630f97a5891c8700e82979e4f233586bfc5042fa73cb70a4e",
                true,
            ),
            // secp384r1_sha384 1.
            (
                Curve::P384,
                key384,
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                 274edebfe76f65fbd51ad2f14898b95b",
                "3064023032401249714e9091f05a5e109d5c1216fdc05e98614261aa0dbd9e9cd441\
                 5dee29238afbd3b103c1e40ee5c9144aee0f02304326756fb2c4fd726360dd6479b5\
                 849478c7a9d054a833a58c1631c33b63c3441336ddf2c7fe0ed129aae6d4ddfeb753",
                true,
            ),
            // secp384r1_sha256 1: a hash shorter than the order.
            (
                Curve::P384,
                key384,
                EMPTY256,
                "3065023100d670d637fcb2da85a22f74ac92939ee2ee5e7d1bb8d6d0afd6f1ef0f88\
                 3a43872ba285430d4df43f93784e1cd6e6f63702303774da5d699f6bd62b329376e3\
                 b6d3612abc67cb945a109d506d3fde45f4c33893c4428250ef6ccfd6e417400344eabb",
                true,
            ),
            // secp256r1_sha256 350: x of k G is past n, and r is x - n.
            (
                Curve::P256,
                large256,
                hash_large256,
                "303502104319055358e8617b0c46353d039cdaab022100ffffffff00000000ffff\
                 ffffffffffffbce6faada7179e84f3b9cac2fc63254e",
                true,
            ),
            // secp256r1_sha256 351: the same with r = x, not below n.
            (
                Curve::P256,
                large256,
                hash_large256,
                "3046022100ffffffff00000001000000000000000000000000ffffffffffffffff\
                 fffffffc022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9\
                 cac2fc63254e",
                false,
            ),
            // secp384r1_sha384 382 and 383, the same on P-384.
            (
                Curve::P384,
                large384,
                hash_large384,
                "304d0218389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68b023100ffff\
                 ffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0d\
                 b248b0a77aecec196accc52970",
                true,
            ),
            (
                Curve::P384,
                large384,
                hash_large384,
                "3066023100ffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 fffffffeffffffff0000000000000000fffffffe023100ffffffffffffffffffff\
                 ffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec19\
                 6accc52970",
                false,
            ),
        ] {
            assert_eq!(
                verify(&curve, &hex(key), &hex(hash), &hex(signature)),
                valid
            );
        }
    }

    /// The valid P-256 case with one thing changed at a time.
    #[test]
    fn rejects() {
        let (key, hash, signature) = (hex(KEY256), hex(EMPTY256), hex(SIG256));
        assert!(verify(&Curve::P256, &key, &hash, &signature));
        assert!(!verify(&Curve::P384, &key, &hash, &signature));
        let mut wrong = hex(EMPTY256);
        wrong[31] ^= 1;
        assert!(!verify(&Curve::P256, &key, &wrong, &signature));
        assert!(!verify(&Curve::P256, &key, &hash[..31], &signature));
        // Keys: off the curve, X = p, compressed, infinity, cut short.
        let mut off = hex(KEY256);
        off[64] ^= 1;
        let mut big = hex(KEY256);
        big[1..33].copy_from_slice(&hex(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ));
        let mut compressed = hex(KEY256);
        compressed[0] = 3;
        for bad in [&off[..], &big, &compressed[..33], &[0], &key[..64], &[]] {
            assert!(!verify(&Curve::P256, bad, &hash, &signature));
        }
        // Signatures: r and s swapped; the same numbers in other BER
        // encodings; r or s of 0 or n; truncated and extended.
        let (r, s) = (&signature[4..37], &signature[39..]);
        let n = "00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        for bad in [
            der(&[0x30, 0x45], &[&[2, 0x20], s, &[2, 0x21], r]),
            der(&[0x30, 0x46], &[&[2, 0x21], r, &[2, 0x21, 0], s]),
            der(&[0x30, 0x44], &[&[2, 0x20], &r[1..], &[2, 0x20], s]),
            der(&[0x30, 0x81, 0x45], &[&[2, 0x21], r, &[2, 0x20], s]),
            der(&[0x30, 0x45], &[&[2, 0x81, 0x21], r, &[2, 0x20], s]),
            der(&[0x31, 0x45], &[&[2, 0x21], r, &[2, 0x20], s]),
            der(&[0x30, 0x45], &[&[3, 0x21], r, &[2, 0x20], s]),
            der(&[0x30, 0x46], &[&[2, 0x21], r, &[2, 0x20], s, &[0]]),
            der(&[0x30, 0x45], &[&[2, 0x21], r, &[2, 0x20], s, &[0]]),
            der(&[0x30, 0x44], &[&[2, 0x21], r, &[2, 0x20], &s[..31]]),
            der(&[0x30, 0x25], &[&[2, 1, 0], &[2, 0x20], s]),
            der(&[0x30, 0x26], &[&[2, 0x21], r, &[2, 1, 0]]),
            der(&[0x30, 0x46], &[&[2, 0x21], &hex(n), &[2, 0x20], s]),
            der(&[0x30, 0x46], &[&[2, 0x21], r, &[2, 0x21], &hex(n)]),
            der(&[0x30, 0x45], &[&[2, 0x21], r, &[2, 0x20], &s[..30]]),
            Vec::new(),
        ] {
            assert!(!verify(&Curve::P256, &key, &hash, &bad));
        }
        assert!(verify(
            &Curve::P256,
            &key,
            &hash,
            &der(&[0x30, 0x45], &[&[2, 0x21], r, &[2, 0x20], s])
        ));
    }

    fn der(head: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(head);
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    /// FIPS 186-4's base points, x and y, plain.
    const G256: [Fe; 2] = [
        [
            0xf4a13945d898c296,
            0x77037d812deb33a0,
            0xf8bce6e563a440f2,
            0x6b17d1f2e12c4247,
            0,
            0,
        ],
        [
            0xcbb6406837bf51f5,
            0x2bce33576b315ece,
            0x8ee7eb4a7c0f9e16,
            0x4fe342e2fe1a7f9b,
            0,
            0,
        ],
    ];
    const G384: [Fe; 2] = [
        [
            0x3a545e3872760ab7,
            0x5502f25dbf55296c,
            0x59f741e082542a38,
            0x6e1d3b628ba79b98,
            0x8eb1c71ef320ad74,
            0xaa87ca22be8b0537,
        ],
        [
            0x7a431d7c90ea0e5f,
            0x0a60b1ce1d7e819d,
            0xe9da3113b5f0b8c0,
            0xf8f41dbd289a147c,
            0x5d9e98bf9292dc29,
            0x3617de4a96262c6f,
        ],
    ];

    /// The constants beside FIPS 186-4's: -m^-1 and R^2 mod m for each
    /// modulus, G's table, and n G at infinity.
    #[test]
    fn constants() {
        let mut key = Vec::new();
        for (curve, params, limbs, base, count) in [
            (Curve::P256, &P256, 4, G256, BASE_P256),
            (Curve::P384, &P384, 6, G384, TABLE),
        ] {
            for modulus in [&params.p, &params.n] {
                assert_eq!(modulus.m[0].wrapping_mul(modulus.m0inv), u64::MAX);
                let mut rr = [0; LIMBS];
                rr[0] = 1;
                for _ in 0..2 * 64 * limbs {
                    rr = add_mod(&modulus.m[..limbs], &rr[..limbs], &rr[..limbs]);
                }
                assert_eq!(rr, modulus.rr);
            }
            // The table's (x, y) is the Jacobian (X, Y, Z) that adding G
            // gives when x Z^2 = X and y Z^3 = Y.
            key.clear();
            key.push(4);
            for coordinate in base {
                for limb in coordinate.iter().take(limbs).rev() {
                    key.extend_from_slice(&limb.to_be_bytes());
                }
            }
            let g = public_point(&curve, &key).unwrap();
            // G added to infinity is G.
            let mut twice = infinity();
            add_affine(&curve, &mut twice, &g);
            double(&curve, &mut twice);
            let mut multiple = infinity();
            add_affine(&curve, &mut multiple, &g);
            for digit in (1..2 * i8::try_from(count).unwrap()).step_by(2) {
                let entry = base_multiple(&curve, digit);
                let zz = fsqr(&curve, &multiple.z);
                assert_eq!(fmul(&curve, &entry.x, &zz), multiple.x);
                let zzz = fmul(&curve, &zz, &multiple.z);
                assert_eq!(fmul(&curve, &entry.y, &zzz), multiple.y);
                add(&curve, &mut multiple, &twice);
            }
            let mut one = [0; LIMBS];
            one[0] = 1;
            let mut sum = infinity();
            combine(&curve, &params.n.m, &g, &[0; LIMBS], &mut sum);
            assert!(is_zero(&sum.z));
            let (below_n, _) = sub_limbs(&params.n.m, &one);
            combine(&curve, &one, &g, &below_n, &mut sum);
            assert!(is_zero(&sum.z));
            combine(&curve, &one, &g, &one, &mut sum);
            assert!(!is_zero(&sum.z));
        }
    }

    /// The P-256 reduction agrees with the generic one, up to (p - 1)^2,
    /// and squares agree with products on both curves.
    #[test]
    fn reductions() {
        let mut top = P256.p.m;
        top[0] -= 1;
        let mut a = P256.b;
        for _ in 0..1000 {
            for b in [a, top, G256[0], [1, 0, 0, 0, 0, 0], [0; LIMBS]] {
                let t = product(&a[..4], &b[..4]);
                assert_eq!(reduce_p256(&t), reduce(&P256.p.m[..4], 1, t));
                assert_eq!(fsqr(&Curve::P256, &b), fmul(&Curve::P256, &b, &b));
            }
            a = fmul(&Curve::P256, &a, &G256[0]);
        }
        let t = product(&top[..4], &top[..4]);
        assert_eq!(reduce_p256(&t), reduce(&P256.p.m[..4], 1, t));
        top = P384.p.m;
        top[0] -= 1;
        a = P384.b;
        for _ in 0..1000 {
            for b in [a, top] {
                assert_eq!(fsqr(&Curve::P384, &b), fmul(&Curve::P384, &b, &b));
            }
            a = fmul(&Curve::P384, &a, &G384[0]);
        }
    }

    /// s s^-1 = 1 mod n for the ends of [1, n - 1] and values between,
    /// each with many and few factors of two along the way.
    #[test]
    fn scalar_inverse() {
        let mut one = [0; LIMBS];
        one[0] = 1;
        for (curve, params) in [(Curve::P256, &P256), (Curve::P384, &P384)] {
            let (top, _) = sub_limbs(&params.n.m, &one);
            let mut s = params.n.rr;
            let mut power = one;
            for _ in 0..200 {
                for value in [s, top, one, power] {
                    let inverse = invert_scalar(&curve, &value);
                    let product = nmul(&curve, &nmul(&curve, &value, &inverse), &params.n.rr);
                    assert_eq!(product, one);
                }
                s = nmul(&curve, &s, &params.n.rr);
                power = super::add_mod(&params.n.m, &power, &power);
            }
        }
    }

    /// One P-256 verification, as of a certificate or a handshake.
    #[bench]
    fn verify_p256(b: &mut Bencher) {
        let (key, hash, signature) = (hex(KEY256), hex(EMPTY256), hex(SIG256));
        b.iter(|| verify(&Curve::P256, &key, &hash, &signature));
    }

    /// One P-384 verification.
    #[bench]
    fn verify_p384(b: &mut Bencher) {
        let key = hex(
            "0429bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61\
             ef182e155a54345a5e8e5e88f064e5bc9a525ab7f764dad3dae1468c2b419f3b62b9\
             ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3",
        );
        let hash = hex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
        );
        let signature = hex(
            "3064023032401249714e9091f05a5e109d5c1216fdc05e98614261aa0dbd9e9cd441\
             5dee29238afbd3b103c1e40ee5c9144aee0f02304326756fb2c4fd726360dd6479b5\
             849478c7a9d054a833a58c1631c33b63c3441336ddf2c7fe0ed129aae6d4ddfeb753",
        );
        b.iter(|| verify(&Curve::P384, &key, &hash, &signature));
    }
}
