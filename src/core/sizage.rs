#[derive(Debug, PartialEq)]
pub struct Sizage {
    pub hs: u16,
    pub ss: u16,
    pub ls: u16,
    pub fs: u16,
}

impl Sizage {
    pub fn new(hs: u16, ss: u16, fs: u16, ls: u16) -> Sizage {
        Self { hs, ss, ls, fs }
    }
}
