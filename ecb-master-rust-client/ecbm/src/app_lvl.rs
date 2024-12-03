use std::io::Read;
use std::io::Write;
use std::time::Duration;

use iso7816_tlv::simple::Tlv;
use iso7816_tlv::simple::Tag;
use log::trace;
use log::warn;
use serde::Deserialize;
use serde::Serialize;

use crate::packet;
use crate::Error;
use crate::Ecbm;
use crate::LibError;
use crate::ResponseError;

pub mod signals {
    pub const RESET: u16 = 0;
    pub const INFO: u16 = 1;
    pub const ADDR: u16 = 2;
    pub const SERIAL: u16 = 13;
    pub const AUTH_KEY: u16 = 14;
    pub const PICK: u16 = 15;

    pub const BOOT_BEGIN: u16 = 16;
    pub const BOOT_END: u16 = 17;
    pub const BOOT_FW_KEY: u16 = 19;
    pub const BOOT_WRITE: u16 = 20;
    pub const BOOT_APP_INFO: u16 = 22;
    pub const BOOT_GO_APP: u16 = 23;
}

pub mod tlv {
    pub const NAME: u8 = 1;         // String
    pub const VERSION: u8 = 2;      // [u8;3]
    pub const SERIAL: u8 = 3;       // String
    pub const TEST_PHRASE: u8 = 4;  // String
    pub const FW_SIZE: u8 = 5;      // u32
    pub const FW_CRC32: u8 = 6;     // u32
}

pub const FIRMWARE_PACK_FILE_EXTENSION: &str = "ecbfw";
pub const TEST_PHRASE_LEN: usize = raiden::KEY_SIZE;
pub const TEST_PHRASE: &str = "P(ufbwe)!aLb80b*";
pub const MIN_WRITE_SIZE: usize = raiden::KEY_SIZE;

pub const VERSION_LEN: usize = 3;
pub const DEFAULT_RESET_TIMEOUT: Duration = Duration::from_millis(5000);
pub const DEFAULT_BOOT_BEGIN_END_FW_WRITE_TIMEOUT: Duration = Duration::from_millis(5000);
pub const BOOT_FW_WRITE_TIMEOUT_DIV: f32 = 10.0;
pub const DEFAULT_BOOT_FW_WRITE_BLOCK: usize = 1024;
pub const USER_APP_NO_DATA_ERR: u32 = 61;
pub const USER_APP_TEST_PHRASE_INVALID_ERR: u32 = 4022;
pub const USER_APP_BAD_FILE_ERR: u32 = 9;
pub const MAX_SERIAL_LEN: usize = 31;
pub const FW_FILLER: u8 = packet::ENC_FILLER;

static_assertions::const_assert_eq!(TEST_PHRASE.len(), TEST_PHRASE_LEN);


#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub version: [u8;VERSION_LEN],
    pub serial: String,
}

#[derive(Debug, Clone)]
pub struct BootAppInfo {
    pub name: String,
    pub version: [u8;VERSION_LEN],
    pub checksum: u32,
    pub fw_size: u32,
}

#[derive(Serialize, Deserialize)]
pub struct FirmwarePack {
    pub name: String,
    pub version: [u8;VERSION_LEN],
    pub checksum_origin: u32,
    pub checksum_final: u32,
    pub test_phrase: Option<[u8;TEST_PHRASE_LEN]>,
    pub data: Vec<u8>,
}

impl FirmwarePack {
    pub fn new(name: String, version: [u8;VERSION_LEN], mut data: Vec<u8>) -> Self {
        let nfill: usize = _nfill_fw(data.len());

        for _ in 0..nfill {
            data.push(FW_FILLER);
        }

        let crc_calc = crc::crc32(&data);
        Self {
            name: name,
            version: version,
            checksum_origin: crc_calc,
            checksum_final: crc_calc,
            test_phrase: None,
            data: data,
        }
    }

    pub fn encrypt(&mut self, key: &[u8]) -> Result<(), raiden::Error> {
        raiden::encode_buf(key, &mut self.data)?;
        self.checksum_final = crc::crc32(&self.data);
        self.test_phrase = Some(raiden::encode(key, &_test_phrase_bytes())?.try_into().unwrap());
        Ok(())
    }

    pub fn from_file(path: &str) -> Result<Self, std::io::Error> {
        let fw_pack_raw = std::fs::read(path)?;
        Self::from_slice(&fw_pack_raw)
    }

    pub fn from_slice(fw_pack_raw: &[u8]) -> Result<Self, std::io::Error> {
        match rmp_serde::from_slice::<Self>(&fw_pack_raw) {
            Ok(v) => {
                let crc_calc = crc::crc32(&v.data);
                let crc_stored_final = v.checksum_final;
                let crc_stored_origin = v.checksum_origin;
                if crc_stored_final != crc_calc {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!(
                        "Firmware pack corrupted: Calculated checksum of firmware(0x{crc_calc:08X}) 
                        mismatch with stored final in pack(0x{crc_stored_final:08X}).")));
                }
                if (crc_stored_origin != crc_stored_final) && v.test_phrase.is_none() {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!(
                        "Firmware pack corrupted: origin checksum(0x{crc_stored_origin:08X}) mismatch with 
                        final(0x{crc_stored_final:08X}), but test phrase not set.")));
                }
                if v.data.len() % MIN_WRITE_SIZE != 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!(
                        "Firmware pack incorrect: data.len({}) not multiple of MIN_WRITE_SIZE({MIN_WRITE_SIZE}).",
                        v.data.len())));
                }
                Ok(v)
            },
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                format!("Fail to decode ecb firmware pack: {err:?}."))),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).unwrap()
    }

    pub fn to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let self_raw = self.to_vec();
        std::fs::write(path, self_raw)
    }
}


const fn _nfill_fw(ndata: usize) -> usize {
    let nfill = MIN_WRITE_SIZE - (ndata % MIN_WRITE_SIZE);
    if nfill < MIN_WRITE_SIZE {
        nfill
    } else {
        0
    }
}

pub fn upload_firmware<S, F>(
    ecbm: &mut Ecbm<S>,
    addr: u8,
    fw_pack: &FirmwarePack,
    write_block_size: Option<usize>,
    timeout: Option<Duration>,
    progress: Option<F>)
    -> Result<(), Error>
    where S: Read + Write + Send + 'static,
          F: Fn(String, u32)
{
    let block_size = match write_block_size {
        Some(v) => {
            if v % MIN_WRITE_SIZE != 0 {
                return Err(Error::Lib(LibError::IncorrectWriteBlockSize(v)));
            }
            v
        },
        None => DEFAULT_BOOT_FW_WRITE_BLOCK,
    };

    let timeout_begin_end = match timeout {
        Some(v) => v,
        None => DEFAULT_BOOT_BEGIN_END_FW_WRITE_TIMEOUT,
    };
    let timeout_write = timeout_begin_end.div_f32(BOOT_FW_WRITE_TIMEOUT_DIV);

    _set_progress(progress.as_ref(), "Erase", 0);

    // Begin write firmware, clear nvm.
    {
        let mut request = vec![
            Tlv::new(Tag::try_from(tlv::NAME).unwrap(), fw_pack.name.as_bytes().to_vec()).unwrap(),
            Tlv::new(Tag::try_from(tlv::VERSION).unwrap(), fw_pack.version.to_vec()).unwrap(),
            Tlv::new(Tag::try_from(tlv::FW_SIZE).unwrap(), (fw_pack.data.len() as u32).to_be_bytes().to_vec()).unwrap(),
        ];
        if let Some(test_phrase) = fw_pack.test_phrase {
            request.push(Tlv::new(Tag::try_from_u8(tlv::TEST_PHRASE).unwrap(), test_phrase.to_vec()).unwrap());
        }
        match ecbm.write_auth(addr, signals::BOOT_BEGIN, &_serialize_tlvs(&request), Some(timeout_begin_end)) {
            Ok(()) => (),
            Err(e) => if e.is_user_app_err_code(USER_APP_TEST_PHRASE_INVALID_ERR) {
                return Err(Error::Response(ResponseError::TestPhraseInvalid));
            } else {
                return Err(e);
            }
        }
    }
    _set_progress(progress.as_ref(), "Write", 0);

    // Write firmware to nvm.
    let mut ptr: usize = 0;
    loop {
        let remain = fw_pack.data.len() - ptr;
        let current_size = if remain > block_size {block_size} else {remain};
        if current_size == 0 {
            break;
        }
        let mut request_raw = Vec::with_capacity(current_size + size_of::<u32>());
        request_raw.extend((ptr as u32).to_be_bytes().to_vec());
        request_raw.extend_from_slice(&fw_pack.data[ptr..ptr+current_size]);
        ecbm.write(addr, signals::BOOT_WRITE, &request_raw, Some(timeout_write))?;
        ptr += current_size;

        _set_progress(progress.as_ref(), "Write", ptr as u32);
    }

    _set_progress(progress.as_ref(), "Finishing", ptr as u32);

    // End write firmware.
    match ecbm.write(addr, signals::BOOT_END, &fw_pack.checksum_origin.to_be_bytes(), Some(timeout_begin_end)) {
        Ok(()) => (),
        Err(e) => if e.is_user_app_err_code(USER_APP_BAD_FILE_ERR) {
            return Err(Error::Response(ResponseError::WrittenFirmwareCorrupted));
        } else {
            return Err(e);
        }
    }

    Ok(())
}

pub fn boot_go_app<S>(ecbm: &mut Ecbm<S>, addr: u8) -> Result<(), Error>
    where S: Read + Write + Send + 'static,
{
    match ecbm.write(addr, signals::BOOT_GO_APP, &[], None) {
        Ok(()) => Ok(()),
        Err(err) => match &err {
            Error::Response(resp_err) => match resp_err {
                ResponseError::SigMismatch { request, answer } => {
                    let _ = request;
                    if *answer == signals::RESET {
                        Ok(())
                    } else {
                        Err(err)
                    }
                },
                _ => Err(err),
            },
            _ => Err(err),
        }
    }
}

pub fn set_fw_key<S>(ecbm: &mut Ecbm<S>, addr: u8, key: &[u8]) -> Result<(), Error>
    where S: Read + Write + Send + 'static,
{
    if key.len() != raiden::KEY_SIZE {
        return Err(Error::Lib(LibError::RaidenError(raiden::Error::KeyIncorrectSize(key.len()))));
    }
    ecbm.write_auth(addr, signals::BOOT_FW_KEY, key, None)
}

pub fn set_auth_key<S>(ecbm: &mut Ecbm<S>, addr: u8, key: &[u8]) -> Result<(), Error>
    where S: Read + Write + Send + 'static,
{
    if key.len() != raiden::KEY_SIZE {
        return Err(Error::Lib(LibError::RaidenError(raiden::Error::KeyIncorrectSize(key.len()))));
    }
    ecbm.write_auth(addr, signals::AUTH_KEY, key, None)
}

pub fn set_serial<S>(ecbm: &mut Ecbm<S>, addr: u8, serial: &str, is_permanent: bool) -> Result<(), Error>
    where S: Read + Write + Send + 'static,
{
    if serial.is_empty() {
        return Err(Error::Lib(LibError::InvalidSerial(format!("empty"))));
    }
    if serial.len() > MAX_SERIAL_LEN {
        return Err(Error::Lib(LibError::InvalidSerial(format!(
            "Too big({}), max len is {MAX_SERIAL_LEN}", serial.len()))));
    }
    if !serial.is_ascii() {
        return Err(Error::Lib(LibError::InvalidSerial(format!("non ascii"))));
    }

    let mut request_raw = Vec::with_capacity(1 + serial.len());
    request_raw.push(if is_permanent {1} else {0});
    request_raw.extend_from_slice(serial.as_bytes());
    ecbm.write_auth(addr, signals::SERIAL, &request_raw, None)
}

pub fn reset_device_to_boot<S>(ecbm: &mut Ecbm<S>, addr: u8, auth: bool, timeout: Option<Duration>) -> Result<Option<BootAppInfo>, Error>
    where S: Read + Write + Send + 'static,
{
    reset_device(ecbm, addr, true, auth, timeout)?;
    let dev_info = read_device_info(ecbm, addr)?;
    let name_lower = dev_info.name.to_lowercase();
    if !name_lower.contains("ecb") || !name_lower.contains("boot") {
        return Err(Error::Response(ResponseError::NoBootloader(dev_info.name)));
    }

    read_boot_app_info(ecbm, addr)
}

pub fn read_device_info<S>(ecbm: &mut Ecbm<S>, addr: u8) -> Result<DeviceInfo, Error>
    where S: Read + Write + Send + 'static,
{
    let app_info_raw = ecbm.read(addr, signals::INFO, None)?;
    let tlvs = Tlv::parse_all(&app_info_raw);
    let mut name: String = String::new();
    let mut version: [u8;VERSION_LEN] = [0;VERSION_LEN];
    let mut serial: String = String::new();
    for tlv in tlvs {
        match tlv.tag().into() {
            tlv::NAME => name = _parse_string_from_tlv(&tlv),
            tlv::VERSION => version = _parse_fixed_array_from_tlv(&tlv)?,
            tlv::SERIAL => serial = _parse_string_from_tlv(&tlv),
            tag => warn!("Unknown tlv tag({tag}) in INFO answer."),
        }
    }

    Ok(DeviceInfo { name: name, version: version, serial: serial })
}

pub fn read_boot_app_info<S>(ecbm: &mut Ecbm<S>, addr: u8) -> Result<Option<BootAppInfo>, Error>
    where S: Read + Write + Send + 'static,
{
    let app_info_raw = match ecbm.read(addr, signals::BOOT_APP_INFO, None) {
        Ok(v) => v,
        Err(err) => if err.is_user_app_err_code(USER_APP_NO_DATA_ERR) {
            return Ok(None);
        } else {
            return Err(err);
        }
    };
    let tlvs = Tlv::parse_all(&app_info_raw);
    let mut name: String = String::new();
    let mut version: [u8;VERSION_LEN] = [0;VERSION_LEN];
    let mut checksum: u32 = 0;
    let mut fw_size: u32 = 0;
    for tlv in tlvs {
        match tlv.tag().into() {
            tlv::NAME => name = _parse_string_from_tlv(&tlv),
            tlv::VERSION => version = _parse_fixed_array_from_tlv(&tlv)?,
            tlv::FW_CRC32 => checksum = _parse_u32_from_tlv(&tlv)?,
            tlv::FW_SIZE => fw_size = _parse_u32_from_tlv(&tlv)?,
            tag => warn!("Unknown tlv tag({tag}) in BOOT_APP_INFO answer."),
        }
    }

    Ok(Some(BootAppInfo { name: name, version: version, checksum: checksum, fw_size: fw_size }))
}

pub fn reset_device<S>(ecbm: &mut Ecbm<S>, addr: u8, long_boot: bool, auth: bool, timeout: Option<Duration>)
    -> Result<(), Error>
    where S: Read + Write + Send + 'static,
{
    trace!("reset_device: addr={addr} long_boot={long_boot} auth={auth}.");
    let reset_arg: [u8;1] = if long_boot {
        [1]
    } else {
        [0]
    };

    let timeout_ = match timeout {
        Some(v) => v,
        None => DEFAULT_RESET_TIMEOUT,
    };

    let result = if auth {
        ecbm.write_auth(addr, signals::RESET, &reset_arg, Some(timeout_))
    } else {
        ecbm.write(addr, signals::RESET, &reset_arg, Some(timeout_))
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) => if e.is_seq_mismatch() {Ok(())} else {Err(e)}
    }
}


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

fn _test_phrase_bytes() -> [u8;TEST_PHRASE_LEN] {
    TEST_PHRASE.as_bytes().try_into().unwrap()
}

fn _parse_fixed_array_from_tlv<const LEN: usize>(tlv: &Tlv) -> Result<[u8;LEN], Error> {
    let tag: u8 = tlv.tag().into();
    if tlv.length() != LEN {
        return Err(Error::Response(ResponseError::InvalidAppData(format!(
            "TLV tag '{}' was found, but it has a incorrect length: {}", tag, tlv.length()))));
    }
    Ok(tlv.value().try_into().unwrap())
}

fn _parse_u32_from_tlv(tlv: &Tlv) -> Result<u32, Error> {
    let tag: u8 = tlv.tag().into();
    if tlv.length() != size_of::<u32>() {
        return Err(Error::Response(ResponseError::InvalidAppData(format!(
            "TLV tag '{}' was found, but it has a incorrect length: {}", tag, tlv.length()))));
    }
    Ok(u32::from_be_bytes(tlv.value().try_into().unwrap()))
}

fn _parse_u16_from_tlv(tlv: &Tlv) -> Result<u16, Error> {
    let tag: u8 = tlv.tag().into();
    if tlv.length() != size_of::<u16>() {
        return Err(Error::Response(ResponseError::InvalidAppData(format!(
            "TLV tag '{}' was found, but it has a incorrect length: {}", tag, tlv.length()))));
    }
    Ok(u16::from_be_bytes(tlv.value().try_into().unwrap()))
}

fn _parse_string_from_tlv(tlv: &Tlv) -> String {
    String::from_utf8_lossy(tlv.value()).to_string()
}

fn _find_tlv<'a>(tlvs: &'a Vec<Tlv>, tag: u8) -> Result<&'a Tlv, Error> {
    for tlv in tlvs {
        let tlv_tag: u8 = tlv.tag().into();
        if tlv_tag == tag {
            return Ok(tlv);
        }
    }
    Err(Error::Response(ResponseError::InvalidAppData(format!("TLV tag '{tag}' must be in answer."))))
}

fn _serialize_tlvs(tlvs: &Vec<Tlv>) -> Vec<u8> {
    const TLV_SERVICE_DATA_SIZE: usize = 2;
    let mut capacity: usize = 0;
    for tlv in tlvs {
        capacity += tlv.length() + TLV_SERVICE_DATA_SIZE;
    }
    let mut raw = Vec::with_capacity(capacity);
    for tlv in tlvs {
        raw.extend(tlv.to_vec());
    }
    raw
}

fn _set_progress<F, T>(func: Option<&F>, stage: &str, val: T)
    where F: Fn(String, T)
{
    if let Some(func) = func {
        (func)(stage.to_string(), val);
    }
}

fn _interpolate_u8(start: u8, end: u8, pos: f32) -> u8 {
    if start > end {
        return start;
    }

    start + ((end - start) as f32 * pos).round() as u8
}
