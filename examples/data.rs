use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use aes::Aes128;
use block_modes::{block_padding::NoPadding, BlockMode, Cbc};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let path = Path::new(&args[1]);
    let fname = path.file_name().unwrap().to_str().unwrap();
    let file = File::open(path).unwrap();
    println!("Filename: {}", fname);

    let mut cursor = BufReader::new(file);

    // "$89bhj^&mk2hd!s9&mxhq9+" was this supposed to be hashed for IV but crappy coding said no?

    let data = untfo_rs::pkg::PkgData::new(
        &mut cursor,
        fname,
        "lkgui781kl789sd!@#%89&^sd",
        "^9gErg2Sx7bnk7@#sdfjnh@",
    );

    println!("{:#?}", data);

    // test for file decomp...
    if let Ok(data) = data {
        let file_entry = &data.files[0];
        type Aes128Cbc = Cbc<Aes128, NoPadding>;

        let mut file = File::open(path).unwrap();
        let seek_pos = data.total_header_size as u64 + file_entry.seek;
        file.seek(SeekFrom::Start(seek_pos)).unwrap();

        let mut buf = vec![0u8; file_entry.size_encrypted as usize];
        file.read_exact(&mut buf).unwrap();

        let fname = Path::new(&file_entry.file_name)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let key = untfo_rs::crypto::data_key(&data.data_key, fname);
        println!("Key: {:X?}", key);
        let aes = Aes128Cbc::new_from_slices(&key, &[0u8; 16]).unwrap();
        let buf = aes.decrypt_vec(&mut buf).unwrap();
        // println!("{:?} {:?}", &buf[..5], &buf[file_entry.size as usize..]);
        // println!("{}\n{}", file_entry.file_name, unsafe { std::str::from_utf8_unchecked(&buf) });
        println!("File: {} {}\n{:?}", file_entry.file_name, fname, &buf);
    }
}
