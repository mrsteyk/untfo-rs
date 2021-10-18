use md5::Context;

pub const ZERO_IV: [u8; 16] = [0; 16];

// key idx doesn't need to be precise, all we care is even/odd
pub fn index_key(idx: u8, key: &[u8; 16], fname: &str) -> Vec<u8> {
    let mut ctx = Context::new();
    ctx.consume(&[2, 0, 0, 0]); // Yes...
    if (idx & 1) != 0 {
        // key, fname
        ctx.consume(key);
        ctx.consume(fname.as_bytes());
    } else {
        // fname, key
        ctx.consume(fname.as_bytes());
        ctx.consume(key);
    }

    ctx.compute().to_vec()
}

pub fn data_key(key: &str, fname: &str) -> Vec<u8> {
    let mut ctx = Context::new();

    ctx.consume(key.as_bytes());
    ctx.consume(fname.as_bytes());

    // "%02x"
    let string = format!("{:x}", ctx.compute());
    // eprintln!("{}", string);
    string.as_bytes()[..16].to_vec()
}
