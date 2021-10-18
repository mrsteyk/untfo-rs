use std::{
    error::Error,
    fmt::Display,
    io::{Read, Seek},
};

use aes::Aes128;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use byteorder::{ReadBytesExt, LE};

pub const PKG_INDEX_HEADER_SIZE: usize = 2 + 1 + 1 + 4;

#[derive(Debug)]
pub enum PkgIndexVersion {
    TFO, // 2
    Unsupported(u16),
}

#[derive(Debug)]
pub enum PkgIndexCipher {
    AES,
    Unsupported(u8),
}

#[derive(Debug)]
pub enum PkgIndexError {
    InvalidVersion(PkgIndexVersion),
    InvalidAlgorithm(PkgIndexCipher),
}

impl Display for PkgIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for PkgIndexError {}

// Index PKG which has plaintext for every (but not limited to!) pkg file
#[derive(Debug)]
pub struct PkgIndex {
    pub version: PkgIndexVersion,
    // no one really needs to know key num?
    pub key_num: u8,            // 13 possible keys in TFO?
    pub cipher: PkgIndexCipher, // I had it written as cypher before...

    pub filenames: Vec<String>,
}

impl PkgIndex {
    pub fn new<R: Read + Seek + ReadBytesExt>(
        c: &mut R,
        fname: &str,
        keys: &[[u8; 16]],
    ) -> Result<Self, Box<dyn Error>> {
        #[cfg(debug_assertions)]
        assert!(
            fname.ends_with(".pkg"),
            "File name should contain .pkg normally???"
        );

        let version = match c.read_u16::<LE>()? {
            2 => PkgIndexVersion::TFO,
            v => {
                return Err(Box::new(PkgIndexError::InvalidVersion(
                    PkgIndexVersion::Unsupported(v),
                )))
            }
        };

        let cipher = match c.read_u8()? {
            2 => PkgIndexCipher::AES,
            v => {
                return Err(Box::new(PkgIndexError::InvalidAlgorithm(
                    PkgIndexCipher::Unsupported(v),
                )))
            }
        };

        let key_num = c.read_u8()?;
        #[cfg(debug_assertions)]
        assert!(
            key_num < 13,
            "Only 13 keys are valid, potential integrity checker?"
        );

        let file_size = c.read_u32::<LE>()?;
        let mut file = Vec::<u8>::with_capacity(file_size as usize);
        c.read_to_end(&mut file)?;
        #[cfg(debug_assertions)]
        {
            assert_eq!(
                file_size,
                file.len() as u32,
                "Non trivial index PKG, Nexon didn't produce those"
            );
            assert!(file_size <= file.len() as u32, "Шиз");
        }

        let filenames = {
            let key = &keys[key_num as usize / 2];
            let key = crate::crypto::index_key(key_num, key, fname);

            match cipher {
                PkgIndexCipher::AES => {
                    // Index files use proper cryptography compared to data files...
                    type Aes128Cbc = Cbc<Aes128, Pkcs7>;
                    let aes = Aes128Cbc::new_from_slices(key.as_slice(), &crate::crypto::ZERO_IV)?;
                    let data = aes.decrypt_vec(&file)?;
                    std::str::from_utf8(&data).unwrap()
                        .split("\r\n")
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                }
                _ => unimplemented!("Scream, because you got the non TFO index file OR we are not aware of such version")
            }
        };

        Ok(Self {
            version,
            key_num,
            cipher,

            filenames,
        })
    }
}
