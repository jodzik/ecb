use std::num::Wrapping;

use thiserror::Error;

pub const BLOCK_SIZE: usize = 8;
pub const KEY_SIZE: usize = 16;


#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("Data size({0}) not multiple of encryption block size(#BLOCK_SIZE")]
    DataNotMultipleOfBlockSize(usize),
    #[error("Key size({0}) not equal #KEY_SIZE")]
    KeyIncorrectSize(usize),
}


fn _encode_block(key: &[u32; 4], data: &[u8], result: &mut [u8]) {
    let mut b0 = Wrapping(u32::from_ne_bytes(data[0..BLOCK_SIZE/2].try_into().unwrap()));
    let mut b1 = Wrapping(u32::from_ne_bytes(data[BLOCK_SIZE/2..BLOCK_SIZE].try_into().unwrap()));
    let mut k: [Wrapping<u32>; 4] = [Wrapping(key[0]), Wrapping(key[1]), Wrapping(key[2]), Wrapping(key[3])];

	for i in 0..KEY_SIZE {
        k[i % 4] = (k[0] + k[1]) + ((k[2] + k[3]) ^ (k[0] << ((k[2] & Wrapping(0x1F)).0 as usize)));
		let sk = k[i % 4];
		b0 += ((sk + b1) << 9) ^ ((sk - b1) ^ ((sk + b1) >> 14));
		b1 += ((sk + b0) << 9) ^ ((sk - b0) ^ ((sk + b0) >> 14));
	}

	result[0..BLOCK_SIZE/2].copy_from_slice(&b0.0.to_ne_bytes());
	result[BLOCK_SIZE/2..BLOCK_SIZE].copy_from_slice(&b1.0.to_ne_bytes());
}

fn _decode_block(key: &[u32], data: &[u8], result: &mut [u8]) {
    let mut b0 = Wrapping(u32::from_ne_bytes(data[0..BLOCK_SIZE/2].try_into().unwrap()));
    let mut b1 = Wrapping(u32::from_ne_bytes(data[BLOCK_SIZE/2..BLOCK_SIZE].try_into().unwrap()));
    let mut k: [Wrapping<u32>; 4] = [Wrapping(key[0]), Wrapping(key[1]), Wrapping(key[2]), Wrapping(key[3])];
	let mut subkeys: [Wrapping<u32>; KEY_SIZE] = [Wrapping(0); KEY_SIZE];

	for i in 0..KEY_SIZE {
        k[i % 4] = (k[0] + k[1]) + ((k[2] + k[3]) ^ (k[0] << ((k[2] & Wrapping(0x1F)).0 as usize)));
        subkeys[i] = k[i % 4];
    }

	for i in (0..KEY_SIZE).rev() {
		b1 -= ((subkeys[i] + b0) << 9) ^ ((subkeys[i] - b0) ^ ((subkeys[i] + b0) >> 14));
		b0 -= ((subkeys[i] + b1) << 9) ^ ((subkeys[i] - b1) ^ ((subkeys[i] + b1) >> 14));
	}

	result[0..BLOCK_SIZE/2].copy_from_slice(&b0.0.to_ne_bytes());
	result[BLOCK_SIZE/2..BLOCK_SIZE].copy_from_slice(&b1.0.to_ne_bytes());
}

fn _key_to_u32(key: &[u8]) -> [u32; 4] {
    let key_own: [u8; KEY_SIZE] = key.try_into().unwrap();
    return [
        u32::from_le_bytes(key_own[0..4].try_into().unwrap()),
        u32::from_le_bytes(key_own[4..8].try_into().unwrap()),
        u32::from_le_bytes(key_own[8..12].try_into().unwrap()),
        u32::from_le_bytes(key_own[12..16].try_into().unwrap())
    ];
}

pub fn encode(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY_SIZE {
        return  Err(Error::KeyIncorrectSize(key.len()));
    }
    if data.len() % BLOCK_SIZE != 0 {
        return Err(Error::DataNotMultipleOfBlockSize(data.len()));
    }

    let mut result: Vec<u8> = vec![0; data.len()];
    let key_u32 = _key_to_u32(key);

	for i in (0..data.len()).step_by(BLOCK_SIZE) {
		_encode_block(&key_u32, &data[i..i+BLOCK_SIZE], &mut result[i..i+BLOCK_SIZE]);
	}

    return Ok(result);
}

pub fn decode(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY_SIZE {
        return  Err(Error::KeyIncorrectSize(key.len()));
    }
    if data.len() % BLOCK_SIZE != 0 {
        return Err(Error::DataNotMultipleOfBlockSize(data.len()));
    }

    let mut result: Vec<u8> = vec![0; data.len()];
    let key_u32 = _key_to_u32(key);

	for i in (0..data.len()).step_by(BLOCK_SIZE) {
		_decode_block(&key_u32, &data[i..i+BLOCK_SIZE], &mut result[i..i+BLOCK_SIZE]);
	}

    return Ok(result);
}

pub fn encode_buf(key: &[u8], data_buf: &mut [u8]) -> Result<(), Error> {
    if key.len() != KEY_SIZE {
        return  Err(Error::KeyIncorrectSize(key.len()));
    }
    if data_buf.len() % BLOCK_SIZE != 0 {
        return Err(Error::DataNotMultipleOfBlockSize(data_buf.len()));
    }

    let key_u32 = _key_to_u32(key);
	let mut buf: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

	for i in (0..data_buf.len()).step_by(BLOCK_SIZE) {
		_encode_block(&key_u32, &data_buf[i..i+BLOCK_SIZE], &mut buf);
        data_buf[i..i+BLOCK_SIZE].copy_from_slice(&buf);
	}

    Ok(())
}

pub fn decode_buf(key: &[u8], data_buf: &mut [u8]) -> Result<(), Error> {
    if key.len() != KEY_SIZE {
        return  Err(Error::KeyIncorrectSize(key.len()));
    }
    if data_buf.len() % BLOCK_SIZE != 0 {
        return Err(Error::DataNotMultipleOfBlockSize(data_buf.len()));
    }

    let key_u32 = _key_to_u32(key);
	let mut buf: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

	for i in (0..data_buf.len()).step_by(BLOCK_SIZE) {
		_decode_block(&key_u32, &data_buf[i..i+BLOCK_SIZE], &mut buf);
        data_buf[i..i+BLOCK_SIZE].copy_from_slice(&buf);
	}

    Ok(())
}

pub fn nfill(ndata: usize) -> usize {
    let nfill = BLOCK_SIZE - (ndata % BLOCK_SIZE);
    if nfill < BLOCK_SIZE {
        nfill
    } else {
        0
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    fn encrypt_decrypt_one_block_equal() -> Result<(), Error> {
        const DATA: [u8;8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let encrypted = encode(&KEY, &DATA)?;
        let decrypted = decode(&KEY, &encrypted)?;
        assert_eq!(DATA.to_vec(), decrypted);
        Ok(())
    }

    #[test]
    fn encrypt_reference_equal() -> Result<(), Error> {
        const DATA: [u8;8] = [0, 1, 2, 3, 4, 5, 6, 7];
        const REFERENCE: [u8;8] = [0x3E, 0x7F, 0xF3, 0x69, 0xDA, 0xD9, 0x16, 0xBC];
        let encrypted = encode(&KEY, &DATA)?;
        assert_eq!(REFERENCE.to_vec(), encrypted);
        Ok(())
    }

    #[test]
    fn try_encrypt_half_block() -> Result<(), Error> {
        const DATA: [u8;4] = [0, 1, 2, 3];
        let encrypted = encode(&KEY, &DATA);
        assert_eq!(Result::Err(Error::DataNotMultipleOfBlockSize), encrypted);
        Ok(())
    }

    #[test]
    fn try_encrypt_with_incorrect_key() -> Result<(), Error> {
        const KEY: [u8; KEY_SIZE - 1] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        const DATA: [u8;8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let encrypted = encode(&KEY, &DATA);
        assert_eq!(Result::Err(Error::KeyIncorrectSize), encrypted);
        Ok(())
    }
}
