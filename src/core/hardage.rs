use crate::error;

pub(crate) fn hardage(c: char) -> error::Result<i32> {
    match c {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0' | '4' | '5' | '6' => Ok(2),
        '1' | '2' | '3' | '7' | '8' | '9' => Ok(4),
        '-' => Err(Box::new(error::Error::UnexpectedCode(
            "count code start".to_owned(),
        ))),
        '_' => Err(Box::new(error::Error::UnexpectedCode(
            "op code start".to_owned(),
        ))),
        _ => Err(Box::new(error::Error::UnknownHardage(c.to_string()))),
    }
}

#[cfg(test)]
mod hardage_tests {
    use crate::core::hardage::hardage;

    #[test]
    fn test_hardage() {
        assert_eq!(hardage('A').unwrap(), 1);
        assert_eq!(hardage('G').unwrap(), 1);
        assert_eq!(hardage('b').unwrap(), 1);
        assert_eq!(hardage('z').unwrap(), 1);
        assert_eq!(hardage('1').unwrap(), 4);
        assert_eq!(hardage('0').unwrap(), 2);
    }
}
