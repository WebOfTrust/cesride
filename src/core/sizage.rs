#[derive(Debug, PartialEq)]
pub struct Sizage {
    pub hs: u32,
    pub ss: u32,
    pub ls: u32,
    pub fs: u32,
}

impl Sizage {
    pub fn new(hs: u32, ss: u32, fs: u32, ls: u32) -> Sizage {
        Self { hs, ss, ls, fs }
    }
}
