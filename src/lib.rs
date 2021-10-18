#![forbid(unsafe_code)]

pub mod crypto; // todo: private?
pub mod pkg;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
