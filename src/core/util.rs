use crate::error;

fn b64_char_to_index(c: char) -> u8 {
    match c {
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
        _ => todo!(),
    }
}

pub fn b64_index_to_char(i: u8) -> char {
    match i {
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
        _ => todo!(),
    }
}

pub fn b64_to_u32(b64: &str) -> u32 {
    let mut out: u32 = 0;

    for c in b64.chars() {
        out = (out << 6) + (b64_char_to_index(c) as u32);
    }

    out
}

pub fn b64_to_u64(b64: &str) -> u64 {
    let mut out: u64 = 0;

    for c in b64.chars() {
        out = (out << 6) + (b64_char_to_index(c) as u64);
    }

    out
}

pub fn u32_to_b64(n: u32, length: usize) -> String {
    let mut x = n;
    let mut out = String::new();

    while x > 0 {
        out.insert(0, b64_index_to_char((x % 64).try_into().unwrap()));
        x /= 64;
    }

    for _ in 0..length - out.len() {
        out.insert(0, 'A');
    }

    out
}

pub fn u64_to_b64(n: u64, length: usize) -> String {
    let mut x = n;
    let mut out = String::new();

    while x > 0 {
        out.insert(0, b64_index_to_char((x % 64).try_into().unwrap()));
        x /= 64;
    }

    for _ in 0..length - out.len() {
        out.insert(0, 'A');
    }

    out
}

pub fn code_b2_to_b64(b2: &Vec<u8>, length: usize) -> error::Result<String> {
    let n = ((length + 1) * 3) / 4;

    if n > b2.len() {
        return Err(Box::new(error::Error::Matter(
            "not enough bytes".to_owned(),
        )));
    }

    if length <= 4 {
        let mut bytes: [u8; 4] = [0; 4];
        bytes[..n].copy_from_slice(&b2[..n]);

        let i = u32::from_be_bytes(bytes);
        let tbs = 2 * (length % 4) + (4 - n) * 8;
        Ok(u32_to_b64(i >> tbs, length))
    } else if length <= 8 {
        let mut bytes: [u8; 8] = [0; 8];
        bytes[..n].copy_from_slice(&b2[..n]);

        let i = u64::from_be_bytes(bytes);
        let tbs = 2 * (length % 4) + (8 - n) * 8;
        Ok(u64_to_b64(i >> tbs, length))
    } else {
        return Err(Box::new(error::Error::Matter(
            "unexpected length".to_owned(),
        )));
    }
}

#[cfg(test)]
mod util_tests {
    use crate::core::util;

    #[test]
    fn test_u32_to_b64() {
        assert_eq!(util::u32_to_b64(0, 1), "A");
        assert_eq!(util::u32_to_b64(1, 1), "B");
        assert_eq!(util::u32_to_b64(0, 2), "AA");
        assert_eq!(util::u32_to_b64(1, 2), "AB");
        assert_eq!(util::u32_to_b64(4095, 2), "__");
        assert_eq!(util::u32_to_b64(16777215, 4), "____");
    }

    #[test]
    fn test_b64_to_u32() {
        assert_eq!(util::b64_to_u32("A"), 0);
        assert_eq!(util::b64_to_u32("B"), 1);
        assert_eq!(util::b64_to_u32("AA"), 0);
        assert_eq!(util::b64_to_u32("AB"), 1);
        assert_eq!(util::b64_to_u32("__"), 4095);
        assert_eq!(util::b64_to_u32("____"), 16777215);
    }
}
