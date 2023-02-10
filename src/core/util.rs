use crate::error::{err, Error, Result};

pub fn b64_char_to_index(c: char) -> Result<u8> {
    Ok(match c {
        'A' => 0,
        'B' => 1,
        'C' => 2,
        'D' => 3,
        'E' => 4,
        'F' => 5,
        'G' => 6,
        'H' => 7,
        'I' => 8,
        'J' => 9,
        'K' => 10,
        'L' => 11,
        'M' => 12,
        'N' => 13,
        'O' => 14,
        'P' => 15,
        'Q' => 16,
        'R' => 17,
        'S' => 18,
        'T' => 19,
        'U' => 20,
        'V' => 21,
        'W' => 22,
        'X' => 23,
        'Y' => 24,
        'Z' => 25,
        'a' => 26,
        'b' => 27,
        'c' => 28,
        'd' => 29,
        'e' => 30,
        'f' => 31,
        'g' => 32,
        'h' => 33,
        'i' => 34,
        'j' => 35,
        'k' => 36,
        'l' => 37,
        'm' => 38,
        'n' => 39,
        'o' => 40,
        'p' => 41,
        'q' => 42,
        'r' => 43,
        's' => 44,
        't' => 45,
        'u' => 46,
        'v' => 47,
        'w' => 48,
        'x' => 49,
        'y' => 50,
        'z' => 51,
        '0' => 52,
        '1' => 53,
        '2' => 54,
        '3' => 55,
        '4' => 56,
        '5' => 57,
        '6' => 58,
        '7' => 59,
        '8' => 60,
        '9' => 61,
        '-' => 62,
        '_' => 63,
        _ => {
            return err!(Error::InvalidBase64Character(c));
        }
    })
}

pub fn b64_index_to_char(i: u8) -> Result<char> {
    Ok(match i {
        0 => 'A',
        1 => 'B',
        2 => 'C',
        3 => 'D',
        4 => 'E',
        5 => 'F',
        6 => 'G',
        7 => 'H',
        8 => 'I',
        9 => 'J',
        10 => 'K',
        11 => 'L',
        12 => 'M',
        13 => 'N',
        14 => 'O',
        15 => 'P',
        16 => 'Q',
        17 => 'R',
        18 => 'S',
        19 => 'T',
        20 => 'U',
        21 => 'V',
        22 => 'W',
        23 => 'X',
        24 => 'Y',
        25 => 'Z',
        26 => 'a',
        27 => 'b',
        28 => 'c',
        29 => 'd',
        30 => 'e',
        31 => 'f',
        32 => 'g',
        33 => 'h',
        34 => 'i',
        35 => 'j',
        36 => 'k',
        37 => 'l',
        38 => 'm',
        39 => 'n',
        40 => 'o',
        41 => 'p',
        42 => 'q',
        43 => 'r',
        44 => 's',
        45 => 't',
        46 => 'u',
        47 => 'v',
        48 => 'w',
        49 => 'x',
        50 => 'y',
        51 => 'z',
        52 => '0',
        53 => '1',
        54 => '2',
        55 => '3',
        56 => '4',
        57 => '5',
        58 => '6',
        59 => '7',
        60 => '8',
        61 => '9',
        62 => '-',
        63 => '_',
        _ => {
            return err!(Error::InvalidBase64Index(i));
        }
    })
}

pub fn b64_to_u32(b64: &str) -> Result<u32> {
    let mut out: u32 = 0;

    for c in b64.chars() {
        out = (out << 6) + (b64_char_to_index(c)? as u32);
    }

    Ok(out)
}

pub fn b64_to_u64(b64: &str) -> Result<u64> {
    let mut out: u64 = 0;

    for c in b64.chars() {
        out = (out << 6) + (b64_char_to_index(c)? as u64);
    }

    Ok(out)
}

pub fn u32_to_b64(n: u32, length: usize) -> Result<String> {
    let mut x = n;
    let mut out = String::new();

    while x > 0 {
        out.insert(0, b64_index_to_char((x % 64).try_into().unwrap())?);
        x /= 64;
    }

    for _ in out.len()..length {
        out.insert(0, 'A');
    }

    Ok(out)
}

pub fn u64_to_b64(n: u64, length: usize) -> Result<String> {
    let mut x = n;
    let mut out = String::new();

    while x > 0 {
        out.insert(0, b64_index_to_char((x % 64).try_into().unwrap())?);
        x /= 64;
    }

    for _ in out.len()..length {
        out.insert(0, 'A');
    }

    Ok(out)
}

pub fn code_b2_to_b64(b2: &[u8], length: usize) -> Result<String> {
    let n = ((length + 1) * 3) / 4;

    if n > b2.len() {
        return err!(Error::Matter("not enough bytes".to_string()));
    }

    if length <= 4 {
        let mut bytes: [u8; 4] = [0; 4];
        bytes[..n].copy_from_slice(&b2[..n]);

        let i = u32::from_be_bytes(bytes);
        let tbs = 2 * (length % 4) + (4 - n) * 8;
        Ok(u32_to_b64(i >> tbs, length)?)
    } else if length <= 8 {
        let mut bytes: [u8; 8] = [0; 8];
        bytes[..n].copy_from_slice(&b2[..n]);

        let i = u64::from_be_bytes(bytes);
        let tbs = 2 * (length % 4) + (8 - n) * 8;
        Ok(u64_to_b64(i >> tbs, length)?)
    } else {
        err!(Error::Matter("unexpected length".to_string()))
    }
}

pub fn code_b64_to_b2(code: &str) -> Result<Vec<u8>> {
    let mut i = b64_to_u64(code)?;
    i <<= 2 * (code.len() % 4);
    let n = ((code.len() + 1) * 3) / 4;
    Ok(i.to_be_bytes()[8 - n..8].to_vec())
}

pub fn nab_sextets(binary: &[u8], count: usize) -> Result<Vec<u8>> {
    let n = ((count + 1) * 3) / 4;

    if n > binary.len() {
        return err!(Error::TooSmall(n - binary.len()));
    }

    let mut padded = binary.to_vec();
    let bps = 3 - (binary.len() % 3);
    padded.resize(binary.len() + bps, 0);

    let mut out = Vec::new();
    let mut i: usize = 0;
    loop {
        let n = ((padded[i] as u32) << 16) + ((padded[i + 1] as u32) << 8) + padded[i + 2] as u32;

        out.push(((n & 0xfc0000) >> 18) as u8);
        out.push(((n & 0x03f000) >> 12) as u8);
        out.push(((n & 0x000fc0) >> 6) as u8);
        out.push((n & 0x00003f) as u8);

        i += 3;
        if i >= padded.len() {
            break;
        }
    }

    Ok(out[..count].to_vec())
}

#[cfg(test)]
mod util_tests {
    use crate::core::util;
    use rstest::rstest;

    #[rstest]
    #[case(0, 1, "A")]
    #[case(1, 1, "B")]
    #[case(0, 2, "AA")]
    #[case(1, 2, "AB")]
    #[case(4095, 2, "__")]
    #[case(16777215, 4, "____")]
    fn test_u32_to_b64(#[case] n: u32, #[case] length: usize, #[case] b64: &str) {
        assert_eq!(util::u32_to_b64(n, length).unwrap(), b64);
    }

    #[rstest]
    #[case(0, "A")]
    #[case(1, "B")]
    #[case(0, "AA")]
    #[case(1, "AB")]
    #[case(4095, "__")]
    #[case(16777215, "____")]
    fn test_b64_to_u32(#[case] n: u32, #[case] b64: &str) {
        assert_eq!(util::b64_to_u32(b64).unwrap(), n);
    }

    #[rstest]
    #[case(0, "A")]
    #[case(1, "B")]
    #[case(0, "AA")]
    #[case(1, "AB")]
    #[case(4095, "__")]
    #[case(16777215, "____")]
    #[case(281474976710655, "________")]
    fn test_b64_to_u64(#[case] n: u64, #[case] b64: &str) {
        assert_eq!(util::b64_to_u64(b64).unwrap(), n);
    }

    #[test]
    fn test_b64_char_to_index() {
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut i = 0;
        for c in s.chars() {
            assert_eq!(util::b64_char_to_index(c).unwrap(), i);
            i += 1;
        }
    }

    #[test]
    fn test_b64_index_to_char() {
        let mut chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".chars();
        for i in 0..63 {
            assert_eq!(util::b64_index_to_char(i).unwrap(), chars.next().unwrap());
        }
    }

    #[rstest]
    #[case(&vec![0], 1, "A")]
    #[case(&vec![0, 0, 0, 0, 0, 0], 8, "AAAAAAAA")]
    #[case(&vec![8, 68, 145], 4, "CESR")]
    #[case(&vec![40, 68, 72, 0, 32, 194], 8, "KERIACDC")]
    #[case(&vec![252], 1, "_")]
    #[case(&vec![255, 255, 255, 255, 255, 255], 8, "________")]
    #[case(&vec![244, 0, 1], 4, "9AAB")]
    fn test_code_b2_to_b64(#[case] b2: &Vec<u8>, #[case] length: usize, #[case] b64: &str) {
        assert_eq!(util::code_b2_to_b64(b2, length).unwrap(), b64);
    }

    #[rstest]
    #[case(vec![0], "A")]
    #[case(vec![0, 0, 0, 0, 0, 0], "AAAAAAAA")]
    #[case(vec![8, 68, 145], "CESR")]
    #[case(vec![40, 68, 72, 0, 32, 194], "KERIACDC")]
    #[case(vec![252], "_")]
    #[case(vec![255, 255, 255, 255, 255, 255], "________")]
    #[case(vec![244, 0, 1], "9AAB")]
    fn test_code_b64_to_b2(#[case] b2: Vec<u8>, #[case] b64: &str) {
        assert_eq!(util::code_b64_to_b2(b64).unwrap(), b2);
    }

    #[rstest]
    #[case(&[255, 255, 255], 4, vec![63, 63, 63, 63])]
    #[case(&[255, 255, 255], 4, vec![63, 63, 63, 63])]
    #[case(&[255, 255, 255, 0, 0, 0], 8, vec![63, 63, 63, 63, 0, 0, 0, 0])]
    #[case(&[255], 1, vec![63])]
    #[case(&[127, 127], 2, vec![31, 55])]
    fn test_nab_sextets(#[case] binary: &[u8], #[case] length: usize, #[case] result: Vec<u8>) {
        assert_eq!(util::nab_sextets(binary, length).unwrap(), result);
        assert_eq!(
            util::nab_sextets(&[255, 255, 255, 0, 0, 0], 8).unwrap(),
            vec![63, 63, 63, 63, 0, 0, 0, 0]
        );
        assert_eq!(util::nab_sextets(&[255], 1).unwrap(), vec![63]);
        assert_eq!(util::nab_sextets(&[127, 127], 2).unwrap(), vec![31, 55]);
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(util::b64_char_to_index('#').is_err());
        assert!(util::b64_index_to_char(64).is_err());
        assert!(util::code_b2_to_b64(&[0], 2).is_err());
        assert!(util::code_b2_to_b64(&[0; 32], 9).is_err());
        assert!(util::nab_sextets(&[127, 127], 3).is_err());
    }
}
