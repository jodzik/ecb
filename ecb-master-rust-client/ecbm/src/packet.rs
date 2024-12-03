use std::fmt::Debug;

use crate::error::*;

pub const MAX_PACKET_SIZE: usize = 4096;
pub const SERVICE_DATA_SIZE: usize = 10;
pub const MAX_DATA_SIZE: usize = MAX_PACKET_SIZE - SERVICE_DATA_SIZE;
pub const ENC_FILLER: u8 = 0xFF;

const ADDR_INDEX: usize = 0;
const PD_INDEX: usize = 1;
const PD_TYPE_BIT: u8 = 0;
const PD_TYPE_MASK: u8 = 0b1111;
const PD_DIR_BIT: u8 = 4;
const PD_IS_ENC_BIT: u8 = 5;
const SIGNAL_INDEX: usize = 2;
const NFILL_INDEX: usize = 4;
const SEQ_INDEX: usize = 5;
const DATA_INDEX: usize = 6;
const CRC32_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Answer = 0,
    Request = 1,
}

impl Direction {
    pub fn from_pd(pd: u8) -> Self {
        if pd & (1 << PD_DIR_BIT) > 0 {
            Direction::Request
        } else {
            Direction::Answer
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Write = 0b0000,
    WriteNoAnsw = 0b0010,
    Read = 0b0001,
    StreamOpen = 0b0011,
    StreamClose = 0b0100,
    StreamData = 0b0101,
    EncOpen = 0b0110,
    WriteAuthReq = 0b0111,
    WriteWithAuth = 0b1000,
    Err = 0b1111,
}

impl PacketType {
    pub fn from_pd(pd: u8) -> Result<Self, ResponseError> {
        let ptype_raw = (pd >> PD_TYPE_BIT) & PD_TYPE_MASK;
        if ptype_raw == Self::Write as u8 {
            Ok(Self::Write)
        } else if ptype_raw == Self::WriteNoAnsw as u8 {
            Ok(Self::WriteNoAnsw)
        } else if ptype_raw == Self::Read as u8 {
            Ok(Self::Read)
        } else if ptype_raw == Self::StreamOpen as u8 {
            Ok(Self::StreamOpen)
        } else if ptype_raw == Self::StreamClose as u8 {
            Ok(Self::StreamClose)
        } else if ptype_raw == Self::StreamData as u8 {
            Ok(Self::StreamData)
        } else if ptype_raw == Self::EncOpen as u8 {
            Ok(Self::EncOpen)
        } else if ptype_raw == Self::WriteAuthReq as u8 {
            Ok(Self::WriteAuthReq)
        } else if ptype_raw == Self::WriteWithAuth as u8 {
            Ok(Self::WriteWithAuth)
        } else if ptype_raw == Self::Err as u8 {
            Ok(Self::Err)
        } else {
            Err(ResponseError::UnknownPacketType(ptype_raw))
        }
    }

    pub fn is_write_type(&self) -> bool {
        *self == Self::Write || *self == Self::WriteWithAuth
    }
}

pub struct Packet {
    pub addr: u8,           // [0]
    pub is_enc: bool,       // [1][5]
    pub dir: Direction,     // [1][4]
    pub ptype: PacketType,  // [1][0..4]
    pub sig: u16,           // [2..4]
    nfill: u8,              // [4]
    pub seq: u8,            // [5]
    pub data: Vec<u8>,      // [6..]
    enc_key: Option<[u8; raiden::KEY_SIZE]>,
}

impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("Packet {{ addr: {}, is_enc: {}, dir: {:?}, ptype: {:?}, sig: {}, data.len: {} }}",
            self.addr, self.is_enc, self.dir, self.ptype, self.sig, self.data.len()))
    }
}

impl Packet {
    pub fn new(addr: u8, dir: Direction, ptype: PacketType, sig: u16, seq: u8, data: Option<&[u8]>, enc_key: Option<&[u8]>)
        -> Result<Self, Error>
    {
        Ok(Self {
            addr: addr,
            is_enc: enc_key.is_some(),
            dir: dir,
            ptype: ptype,
            sig: sig,
            nfill: 0,
            seq: seq,
            data: match data {
                Some(data_ptr) => data_ptr.to_vec(),
                None => Vec::new(),
            },
            enc_key: match enc_key {
                Some(enc_key_ptr) => {
                    if enc_key_ptr.len() != raiden::KEY_SIZE {
                        return Err(Error::Lib(LibError::RaidenError(
                            raiden::Error::KeyIncorrectSize(enc_key_ptr.len()))));
                    }
                    Some(enc_key_ptr.try_into().unwrap())
                },
                None => None,
            }
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, LibError> {
        let ndata = self.data.len();
        let nfill = if self.is_enc {raiden::nfill(ndata)} else {0};
        let total_ndata = SERVICE_DATA_SIZE + ndata + nfill;
        let mut raw = vec![0;total_ndata];
        raw[ADDR_INDEX] = self.addr;
        let pd_is_enc: u8 = if self.is_enc {1} else {0};
        let pd: u8 = (self.ptype as u8) | ((self.dir as u8) << PD_DIR_BIT) | (pd_is_enc << PD_IS_ENC_BIT);
        raw[PD_INDEX] = pd;
        raw[SIGNAL_INDEX..SIGNAL_INDEX+size_of::<u16>()].copy_from_slice(&self.sig.to_be_bytes());
        raw[NFILL_INDEX] = nfill as u8;
        raw[SEQ_INDEX] = self.seq;

        for i in 0..ndata {
            raw[DATA_INDEX+i] = self.data[i];
        }

        for i in 0..nfill {
            raw[DATA_INDEX+ndata+i] = ENC_FILLER;
        }

        match self.enc_key {
            Some(enc_key) => {
                raiden::encode_buf(&enc_key, &mut raw[DATA_INDEX..DATA_INDEX+ndata+nfill])?;
            },
            None => ()
        }

        let crc = crc::crc32(&raw[..total_ndata-CRC32_SIZE]);
        raw[total_ndata-CRC32_SIZE..].copy_from_slice(&crc.to_be_bytes());

        return Ok(raw);
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, ResponseError> {
        let raw_size = raw.len();
        if raw.len() < SERVICE_DATA_SIZE {
            return Err(ResponseError::NoServiceData(raw_size));
        }
        let crc_recv = u32::from_be_bytes(raw[raw_size-CRC32_SIZE..].try_into().unwrap());
        let crc_calc = crc::crc32(&raw[..raw_size-CRC32_SIZE]);
        if crc_calc != crc_recv {
            return Err(ResponseError::CrcMismatch);
        }
        let nfill = raw[NFILL_INDEX];
        let is_enc = raw[PD_INDEX] & (1 << PD_IS_ENC_BIT) > 0;
        if nfill > 0 && !is_enc {
            return Err(ResponseError::NfillSetWithoutEnc(nfill));
        }
        let seq = raw[SEQ_INDEX];

        Ok(Self {
            addr: raw[ADDR_INDEX],
            is_enc: is_enc,
            dir: Direction::from_pd(raw[PD_INDEX]),
            ptype: PacketType::from_pd(raw[PD_INDEX])?,
            sig: u16::from_be_bytes(raw[SIGNAL_INDEX..SIGNAL_INDEX+size_of::<u16>()].try_into().unwrap()),
            nfill: nfill,
            seq: seq,
            data: raw[DATA_INDEX..raw_size-CRC32_SIZE].to_vec(),
            enc_key: None,
        })
    }

    pub fn decrypt(&mut self, enc_key: &[u8]) -> Result<(), ResponseError> {
        raiden::decode_buf(enc_key, &mut self.data)?;
        for _ in 0..self.nfill {
            self.data.pop();
        }
        Ok(())
    }
}
