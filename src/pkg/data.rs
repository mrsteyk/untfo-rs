use std::{
    error::Error,
    fmt::Display,
    io::{Cursor, Read, Seek},
};

use aes::Aes128;
use block_modes::{block_padding::NoPadding, BlockMode, Cbc};
use byteorder::{ReadBytesExt, LE};

type Aes128Cbc = Cbc<Aes128, NoPadding>;

#[derive(Debug)]
pub enum PkgDataError {
    InvalidHash(std::str::Utf8Error),
    InvalidHeaderKey,
}

impl Error for PkgDataError {}
impl Display for PkgDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// also known as FileHeader in Nexon's codebase?
#[derive(Debug)]
pub struct PkgFileEntry {
    pub file_name: String,
    pub seek: u64, // 261 + total_header_size
    pub size_encrypted: u64,
    pub size: u64,
    pub unk_285: u8, // idk???
    pub encrypted: bool,
}

#[derive(Debug)]
pub struct PkgData {
    pub hash: String, // first 33 bytes
    pub file_count: u32,
    pub unk: [u8; 4],

    pub data_key: String, // ???

    // needed for seek shit
    pub total_header_size: usize,
    pub files: Vec<PkgFileEntry>,
}

impl PkgData {
    pub fn new<R: Read + Seek + ReadBytesExt>(
        c: &mut R,
        fname: &str,
        header: &str,
        data: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let hash = {
            let mut hash_buf = [0u8; 33];
            c.read_exact(&mut hash_buf)?;
            match std::str::from_utf8(&hash_buf[..32]) {
                Ok(v) => v.to_owned(),
                Err(v) => return Err(Box::new(PkgDataError::InvalidHash(v))),
            }
        };

        let header_key = crate::crypto::data_key(header, fname);
        let header = {
            // 12 in reality but we round to a round/block since AES
            let mut header_buf = [0u8; 16];
            c.read_exact(&mut header_buf)?;

            // In this instance we couldn't care less about padding???
            // 128 bits when MD5 in hex is 256...
            let aes = Aes128Cbc::new_from_slices(&header_key, &crate::crypto::ZERO_IV)?;
            aes.decrypt_vec(&header_buf)?
        };
        let header = &header[..12];

        // Game does this as a shitty check?
        if header[0..4] != [0, 0, 0, 0] {
            eprintln!("{:?}", header);
            return Err(Box::new(PkgDataError::InvalidHeaderKey));
        }
        let file_count = (header[4] as u32)
            | ((header[5] as u32) << 8)
            | ((header[6] as u32) << 16)
            | ((header[7] as u32) << 24);

        let mut unk = [0u8; 4];
        unk.copy_from_slice(&header[8..]);

        let total_header_size = 33 + 16 + (288 * file_count as usize);

        let files = {
            let mut ret = Vec::<PkgFileEntry>::with_capacity(file_count as usize);

            for _ in 0..file_count {
                // 287 in reality???
                let mut file_buf = [0u8; 288];
                c.read_exact(&mut file_buf)?;

                let aes = Aes128Cbc::new_from_slices(&header_key, &crate::crypto::ZERO_IV)?;
                let file = aes.decrypt(&mut file_buf)?;
                let file = &file[..287];

                // First thing is file path of 260+1(NT) bytes...
                let file_name = {
                    let slice = &file[..260]; // skip guranteed NT
                    let npos = slice.iter().position(|c| *c == 0).unwrap_or(260);
                    std::str::from_utf8(&slice[..npos])?.to_owned() // This would be sad if we error out here...
                };

                // I got really lazy...
                let mut c = Cursor::new(&file[261..]);
                let seek = c.read_u64::<LE>()?;
                let size_encrypted = c.read_u64::<LE>()?;
                let size = c.read_u64::<LE>()?;
                let unk_285 = c.read_u8()?; // compressed perhaps???
                let encrypted = c.read_u8()? != 0;

                ret.push(PkgFileEntry {
                    file_name,
                    seek,
                    size_encrypted,
                    size,
                    unk_285,
                    encrypted,
                })
            }

            ret
        };

        Ok(Self {
            hash,
            file_count,
            unk,

            data_key: data.to_owned(),

            total_header_size,
            files,
        })
    }
}
