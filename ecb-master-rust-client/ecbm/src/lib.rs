use std::{fmt::Debug, io::{Read, Write}, sync::{mpsc::{channel, Receiver, SendError, Sender}, Arc, Mutex}, thread::{self, JoinHandle}, time::{self, Duration}};

use framer7b::Framer7b;
use log::trace;
use num_derive::FromPrimitive;

pub mod signals {
    pub const RESET: u16 = 0;
    pub const INFO: u16 = 1;
    pub const ADDR: u16 = 2;
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

pub const KEY_SIZE: usize = raiden::KEY_SIZE;
pub const BLOCK_SIZE: usize = raiden::BLOCK_SIZE;
pub const BROADCAST_ADDR: u8 = 0;
const BROADCAST_ALLOWED_PD_TYPES: [PacketType; 2] = [PacketType::WriteNoAnsw, PacketType::StreamClose];

const STREAM_CLOSE_SEND_PERIOD: Duration = Duration::from_millis(50);
const RECV_THREAD_ON_EAGAIN_SLEEP: Duration = Duration::from_millis(10);
const RECV_THREAD_BUF_SIZE: usize = 256;
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULT_MIN_STREAM_CLOSE_WAIT: Duration = Duration::from_millis(500);
const DEFAULT_STREAM_CLOSE_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_PACKET_SIZE: usize = 4096;
const FRAMER_BUF_SIZE: usize = 4096 * 4096 / 7 + 1;
const SERVICE_DATA_SIZE: usize = 9;
pub const MAX_DATA_SIZE: usize = MAX_PACKET_SIZE - SERVICE_DATA_SIZE;

const ADDR_INDEX: usize = 0;
const PD_INDEX: usize = 1;
const PD_TYPE_BIT: u8 = 0;
const PD_TYPE_MASK: u8 = 0b1111;
const PD_DIR_BIT: u8 = 4;
const PD_IS_ENC_BIT: u8 = 5;
const SIGNAL_INDEX: usize = 2;
const NFILL_INDEX: usize = 4;
const DATA_INDEX: usize = 5;
const FILLER: u8 = 0xFF;
const CRC32_SIZE: usize = 4;

const ANSW_ERR_USER_APP: u8 = 1;
const ANSW_ERR_NO_SIG: u8 = 2;
const ANSW_ERR_NO_OPERATION: u8 = 3;
const ANSW_ERR_ENC_REQUIRED: u8 = 4;
const ANSW_ERR_AUTH_REQUIRED: u8 = 5;
const ANSW_ERR_NO_ENC_SESSION: u8 = 6;
const ANSW_ERR_INTERNAL: u8 = 7;
const ANSW_ERR_INCORRECT_SIGN: u8 = 8;
const ANSW_ERR_ENC_NOT_SUPPORTED: u8 = 9;


type PacketRx = Receiver<Result<Packet, Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, FromPrimitive)]
#[repr(u32)]
pub enum ErrorAnswerInternal {
    #[error("")]
    EncNotAllowed = 1,
    #[error("")]
    NoSign = 2,
    #[error("")]
    RealDataSizeNegative = 3,
    #[error("")]
    DataSizeNotMultipleOfBlockSize = 4,
    #[error("")]
    UnknownPdType = 5,
    #[error("")]
    Unknown,
}

impl From<u32> for ErrorAnswerInternal {
    fn from(code: u32) -> Self {
        match num::FromPrimitive::from_u32(code) {
            Some(value) => value,
            None => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
#[repr(u8)]
pub enum ErrorAnswer {
    #[error("User application error({err_code}) occurred while handling signal: {description}.")]
    UserAppError {
        err_code: u32,
        description: String,
    },
    #[error("User application does'nt have a signal {0}.")]
    NoSig(u16),
    #[error("User application does'nt have a {ptype:?} operation for signal {sig}.")]
    NoOperation {
        ptype: PacketType,
        sig: u16,
    },
    #[error("User application requires encryption for signal {0}.")]
    EncRequired(u16),
    #[error("User application requires authentication write for signal {0}.")]
    AuthRequired(u16),
    #[error("Encryption session not started for device at attr {0}")]
    NoEncryptionSession(u8),
    #[error("Internal error: {0:?}")]
    Internal(ErrorAnswerInternal),
    #[error("Incorrect sign in write with auth request")]
    IncorrectSign,
    #[error("Device at addr {0} do not support encryption")]
    EncryptionNotSupported(u8),
    #[error("Answer has an error type, but error code({0}) not recognized.")]
    Unknown(u8),
}

impl ErrorAnswer {
    fn from_answer(answer: &[u8], addr: u8, ptype: PacketType, sig: u16) -> Result<Self, Error> {
        if answer.len() == 0 {
            return Err(Error::Response(ResponseError::EmptyDataInErrorAnswer));
        }

        match answer[0] {
            ANSW_ERR_USER_APP => {
                if answer.len() < 1 + size_of::<u32>() {
                    return Err(Error::Response(ResponseError::UserAppErrorResponseWithoutCode));
                }
                let user_app_err_code = u32::from_be_bytes(answer[1..1+size_of::<u32>()].try_into().unwrap());
                let description = if answer.len() > 1 + size_of::<u32>() {
                    String::from_utf8_lossy(&answer[1+size_of::<u32>()..]).to_string()
                } else {
                    String::new()
                };
                Ok(Self::UserAppError { err_code: user_app_err_code, description: description })
            },
            ANSW_ERR_NO_SIG => Ok(Self::NoSig(sig)),
            ANSW_ERR_NO_OPERATION => Ok(Self::NoOperation {ptype: ptype, sig: sig}),
            ANSW_ERR_ENC_REQUIRED => Ok(Self::EncRequired(sig)),
            ANSW_ERR_AUTH_REQUIRED => Ok(Self::AuthRequired(sig)),
            ANSW_ERR_NO_ENC_SESSION => Ok(Self::NoEncryptionSession(addr)),
            ANSW_ERR_INTERNAL => {
                if answer.len() < 1 + size_of::<u32>() {
                    return Err(Error::Response(ResponseError::UserAppErrorResponseWithoutCode));
                }
                let user_app_err_code = u32::from_be_bytes(answer[1..1+size_of::<u32>()].try_into().unwrap());
                Ok(Self::Internal(user_app_err_code.into()))
            },
            ANSW_ERR_INCORRECT_SIGN => Ok(Self::IncorrectSign),
            ANSW_ERR_ENC_NOT_SUPPORTED => Ok(Self::EncryptionNotSupported(addr)),
            other => Ok(Self::Unknown(other)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    #[error("Answer has an unknown packet type({0}).")]
    UnknownPacketType(u8),
    #[error("Answer size too small: {0}.")]
    NoServiceData(usize),
    #[error("Answer corrupted: calculated and received crc mismatch.")]
    CrcMismatch,
    #[error("Answer is not encrypted, but 'nfill' has a non-zero value: {0}")]
    NfillSetWithoutEnc(u8),
    #[error("Framer7b error: {0:?}")]
    Framer7bError(framer7b::Error),
    #[error("Answer was not received in {0:?}.")]
    Timeout(Duration),
    #[error("Answer was received, but addr is mismatch: request addr - {request}, answer addr - {answer}.")]
    AddrMismatch {
        request: u8,
        answer: u8,
    },
    #[error("Answer was received, but encryption not equal request: 
            request encrypted - {request}, answer encrypted - {answer}.")]
    IsEncMismatch {
        request: bool,
        answer: bool,
    },
    #[error("Response packet was received, but has a non-answer direction.")]
    NotAnswerDirection,
    #[error("Answer was received, but has a incorrect packet type: 
            request packet type - {request:?}, answer packet type - {answer:?}.")]
    PacketTypeMismatch {
        request: PacketType,
        answer: PacketType,
    },
    #[error("Answer was received, but: {0:?}.")]
    ErrorAnswer(ErrorAnswer),
    #[error("Answer has an error packet type, but data field is empty")]
    EmptyDataInErrorAnswer,
    #[error("Answer has an user application error type, but not contain user application error code.")]
    UserAppErrorResponseWithoutCode,
    #[error("Answer was received, but raiden encryption error occurred: {0:?}.")]
    RaidenError(raiden::Error),
    #[error("Write authentication answer was received, but has an incorrect sign size: {0}.")]
    IncorrectSignInWriteAuthReq(usize),
}

impl From<raiden::Error> for ResponseError {
    fn from(value: raiden::Error) -> Self {
        Self::RaidenError(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LibError {
    #[error("Operation {0:?} not permitted while the stream is open")]
    OperationNotPermittedWhileStreamIsOpen(Operation),
    #[error("Raiden encryption error: {0:?}.")]
    RaidenError(raiden::Error),
    #[error("IO error occurred: {0}")]
    Io(String),
    #[error("Receive channel disconnected, received thread has probably panic.")]
    ReceiveChannelDisconnected,
    #[error("Encryption session for addr {0} was not opened.")]
    EncSessionNotFound(u8),
    #[error("Try request with broadcast addr: operation {0:?} allowed only for the non-broadcast addresses.")]
    TryRequestWithBroadcast(PacketType),
    #[error("Operation {0:?} allowed only for the non-broadcast addresses.")]
    NotAllowedPacketTypeForBroadcast(PacketType),
    #[error("Not implemented.")]
    NotImpl,
}

impl From<raiden::Error> for LibError {
    fn from(value: raiden::Error) -> Self {
        Self::RaidenError(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("Response error: {0:?}")]
    Response(ResponseError),
    #[error("Lib error: {0:?}")]
    Lib(LibError),
}

impl From<LibError> for Error {
    fn from(value: LibError) -> Self {
        Self::Lib(value)
    }
}

impl From<ResponseError> for Error {
    fn from(value: ResponseError) -> Self {
        Self::Response(value)
    }
}

impl From<framer7b::Error> for Error {
    fn from(value: framer7b::Error) -> Self {
        Self::Response(ResponseError::Framer7bError(value))
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Lib(LibError::Io(value.to_string()))
    }
}

impl Into<std::io::Error> for Error {
    fn into(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{self:?}"))
    }
}

impl Error {
    pub fn from_raiden<T>(result: Result<T, raiden::Error>, is_lib: bool) -> Result<T, Self> {
        match result {
            Ok(val) => Ok(val),
            Err(err) => if is_lib {
                Err(Self::Lib(err.into()))
            } else {
                Err(Self::Response(err.into()))
            }
        }
    }
}


/// **Packet**

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    OpenEncryptionSession,
    FlushReceiveThread,
    StreamOpen,
    StreamClose,
    BroadcastWrite,
    Unrecognized,
}

impl From<PacketType> for Operation {
    fn from(value: PacketType) -> Self {
        match value {
            PacketType::EncOpen => Self::OpenEncryptionSession,
            PacketType::Read => Self::Read,
            PacketType::StreamClose => Self::StreamClose,
            PacketType::StreamOpen => Self::StreamOpen,
            PacketType::Write => Self::Write,
            PacketType::WriteAuthReq => Self::Write,
            PacketType::WriteNoAnsw => Self::BroadcastWrite,
            PacketType::WriteWithAuth => Self::Write,
            _ => Self::Unrecognized,
        }
    }
}

struct Packet {
    pub addr: u8,           // [0]
    pub is_enc: bool,       // [1][5]
    pub dir: Direction,     // [1][4]
    pub ptype: PacketType,  // [1][0..4]
    pub sig: u16,           // [2..4]
    nfill: u8,              // [4]
    pub data: Vec<u8>,      // [5..]
    enc_key: Option<[u8; raiden::KEY_SIZE]>,
}

impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("Packet {{ addr: {}, is_enc: {}, dir: {:?}, ptype: {:?}, sig: {}, data.len: {} }}",
            self.addr, self.is_enc, self.dir, self.ptype, self.sig, self.data.len()))
    }
}

impl Packet {

    pub fn new(addr: u8, dir: Direction, ptype: PacketType, sig: u16, data: Option<&[u8]>, enc_key: Option<&[u8]>)
        -> Result<Self, Error>
    {
        Ok(Self {
            addr: addr,
            is_enc: enc_key.is_some(),
            dir: dir,
            ptype: ptype,
            sig: sig,
            nfill: 0,
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

        for i in 0..ndata {
            raw[DATA_INDEX+i] = self.data[i];
        }

        for i in 0..nfill {
            raw[DATA_INDEX+ndata+i] = FILLER;
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

        Ok(Self {
            addr: raw[ADDR_INDEX],
            is_enc: is_enc,
            dir: Direction::from_pd(raw[PD_INDEX]),
            ptype: PacketType::from_pd(raw[PD_INDEX])?,
            sig: u16::from_be_bytes(raw[SIGNAL_INDEX..SIGNAL_INDEX+size_of::<u16>()].try_into().unwrap()),
            nfill: nfill,
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


fn _receive_thread_process<S>(io_stream: Arc<Mutex<S>>, send: Sender<Result<Packet, Error>>)
    -> Result<(), SendError<Result<Packet, Error>>>
    where S: Read + Write,
{
    let mut framer = Framer7b::new(FRAMER_BUF_SIZE);
    let mut buf: [u8; RECV_THREAD_BUF_SIZE] = [0; RECV_THREAD_BUF_SIZE];

    loop {
        let read_result = {
            io_stream.lock().unwrap().read(&mut buf)
        };
        match read_result {
            Ok(read_size) => {
                for i in 0..read_size {
                    match framer.push(buf[i]) {
                        Ok(result) => match result {
                            Some(frame) => match Packet::deserialize(frame) {
                                Ok(packet) => send.send(Ok(packet))?,
                                Err(err) => send.send(Err(err.into()))?,
                            }
                            None => (),
                        }
                        Err(err) => match err {
                            framer7b::Error::UnexpectedBegin => (),
                            framer7b::Error::UnknownFramingByte(_) => (),
                            fatal_err => send.send(Err(fatal_err.into()))?,
                        },
                    }
                }
            },
            Err(err) => match err.kind() {
                std::io::ErrorKind::TimedOut => (),
                std::io::ErrorKind::WouldBlock => thread::sleep(RECV_THREAD_ON_EAGAIN_SLEEP),
                _ => send.send(Err(err.into()))?,
            }
        }
    }
}

fn _receive_thread<S>(io_stream: Arc<Mutex<S>>, send: Sender<Result<Packet, Error>>)
    where S: Read + Write,
{
    match _receive_thread_process(io_stream, send) {
        Err(err) => trace!("_receive_thread: process canceled: fail to send: {err:?}."),
        Ok(()) => log::error!("_receive_thread: process canceled: brake."),
    }
}

fn _receive_packet(rx_io: &mut Receiver<Result<Packet, Error>>, timeout: Duration) -> Result<Packet, Error> {
    const TRY_RECV_SLEEP: Duration = Duration::from_millis(10);
    let start = time::Instant::now();

    loop {
        match rx_io.try_recv() {
            Ok(result) => break result,
            Err(err) => match err {
                std::sync::mpsc::TryRecvError::Disconnected =>
                    break Err(Error::Lib(LibError::ReceiveChannelDisconnected)),
                std::sync::mpsc::TryRecvError::Empty => thread::sleep(TRY_RECV_SLEEP),
            }
        }

        if start.elapsed() > timeout {
            break Err(Error::Response(ResponseError::Timeout(timeout)));
        }
    }
}

fn _stream_thread(
    ctl_rx: Receiver<StreamCtl>,
    packet_rx: PacketRx,
    addr: u8,
    sig: u16,
    key: Option<Vec<u8>>,
    stream_data_tx: Sender<Vec<u8>>) -> PacketRx
{
    loop {
        if let Ok(_) = ctl_rx.try_recv() {
            break;
        }
        if let Ok(result) = packet_rx.try_recv() {
            if let Ok(mut packet) = result {
                if packet.ptype == PacketType::StreamData && packet.addr == addr && packet.sig == sig {
                    if packet.is_enc && key.is_some() {
                        packet.decrypt(&key.as_ref().unwrap()).unwrap();
                    }
                    let _ = stream_data_tx.send(packet.data);
                }
            }
        }
        thread::sleep(RECV_THREAD_ON_EAGAIN_SLEEP);
    }
    packet_rx
}


enum StreamCtl {
    Close,
}

#[derive(Debug, Clone)]
pub struct EncSession {
    pub addr: u8,
    pub key: [u8; raiden::KEY_SIZE],
}

pub struct Ecbm<S> {
    io_stream: Arc<Mutex<S>>,
    packet_rx: Option<PacketRx>,
    stream_ctl: Option<(JoinHandle<PacketRx>, Sender<StreamCtl>)>,
    enc_sessions: Vec<EncSession>,
    timeout: Duration,
    min_stream_close_wait: Duration,
    stream_close_timeout: Duration,
}

impl<S> Ecbm<S>
    where S: Write + Read + Send + 'static,
{
    pub fn new(io_stream: S) -> Self {
        let io_stream_arc = Arc::new(Mutex::new(io_stream));
        let io_stream_arc_receive_th = io_stream_arc.clone();
        let (recv_ch_tx, recv_ch_rx) = channel::<Result<Packet, Error>>();

        thread::spawn(move || _receive_thread(io_stream_arc_receive_th, recv_ch_tx));

        Ecbm {
            io_stream: io_stream_arc,
            packet_rx: Some(recv_ch_rx),
            enc_sessions: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            stream_ctl: None,
            min_stream_close_wait: DEFAULT_MIN_STREAM_CLOSE_WAIT,
            stream_close_timeout: DEFAULT_STREAM_CLOSE_TIMEOUT,
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn set_stream_close_timeout(&mut self, timeout: Duration) {
        self.stream_close_timeout = timeout;
    }

    pub fn set_min_stream_close_wait(&mut self, wait: Duration) {
        self.min_stream_close_wait = wait;
    }

    pub fn open_enc_session(&mut self, addr: u8, enc_key: &[u8]) -> Result<(), Error> {
        let session_key_enc = self._request(addr, 0, None, PacketType::EncOpen, None, Some(self.timeout))?;
        if session_key_enc.len() != raiden::KEY_SIZE {
            return Err(Error::Response(ResponseError::RaidenError(
                raiden::Error::KeyIncorrectSize(session_key_enc.len()))));
        }

        let session_ley = Error::from_raiden(raiden::decode(enc_key, &session_key_enc), true)?;

        if let Ok(session) = self._find_enc_session_mut(addr) {
            session.key = session_ley[..].try_into().unwrap();
        } else {
            self.enc_sessions.push(EncSession { addr: addr, key: session_ley[..].try_into().unwrap() });
        }

        Ok(())
    }

    pub fn drop_enc_session(&mut self, addr: u8) -> Result<(), Error> {
        for i in 0..self.enc_sessions.len() {
            if self.enc_sessions[i].addr == addr {
                self.enc_sessions.remove(i);
                return Ok(());
            }
        }
        Err(Error::Lib(LibError::EncSessionNotFound(addr)))
    }

    pub fn drop_all_enc_sessions(&mut self) {
        self.enc_sessions.clear();
    }

    pub fn find_enc_session<'a>(&'a self, addr: u8) -> Option<&'a EncSession> {
        match self._find_enc_session(addr) {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }

    pub fn read(&mut self, addr: u8, sig: u16, timeout: Option<Duration>) -> Result<Vec<u8>, Error> {
        self._request(addr, sig, None, PacketType::Read, None, timeout)
    }

    pub fn read_enc(&mut self, addr: u8, sig: u16, timeout: Option<Duration>) -> Result<Vec<u8>, Error> {
        let key = self._find_enc_session(addr)?.key.clone();
        self._request(addr, sig, None, PacketType::Read, Some(&key), timeout)
    }

    pub fn write(&mut self, addr: u8, sig: u16, data: &[u8], timeout: Option<Duration>) -> Result<(), Error> {
        self._request(addr, sig, Some(data), PacketType::Write, None, timeout)?;
        Ok(())
    }

    pub fn write_enc(&mut self, addr: u8, sig: u16, data: &[u8], timeout: Option<Duration>) -> Result<(), Error> {
        let key = self._find_enc_session(addr)?.key.clone();
        self._request(addr, sig, Some(data), PacketType::Write, Some(&key), timeout)?;
        Ok(())
    }

    pub fn write_auth(&mut self, addr: u8, sig: u16, data: &[u8], timeout: Option<Duration>) -> Result<(), Error> {
        let key = self._find_enc_session(addr)?.key.clone();
        let sign = self._request(addr, sig, Some(data), PacketType::WriteAuthReq, None, None)?;
        if sign.len() != raiden::BLOCK_SIZE {
            return Err(Error::Response(ResponseError::IncorrectSignInWriteAuthReq(sign.len())));
        }

        let mut sign_data = Vec::with_capacity(sign.len() + data.len());

        for sd in sign {
            sign_data.push(sd);
        }

        for d in data {
            sign_data.push(*d);
        }

        self._request(addr, sig, Some(&sign_data), PacketType::WriteWithAuth, Some(&key), timeout)?;

        Ok(())
    }

    pub fn write_no_answ(&mut self, addr: u8, sig: u16, data: &[u8]) -> Result<(), Error> {
        self._request_no_answ(addr, sig, Some(data), PacketType::WriteNoAnsw, None)?;
        Ok(())
    }

    pub fn write_no_answ_enc(&mut self, addr: u8, sig: u16, data: &[u8]) -> Result<(), Error> {
        let key = self._find_enc_session(addr)?.key.clone();
        self._request_no_answ(addr, sig, Some(data), PacketType::WriteNoAnsw, Some(&key))?;
        Ok(())
    }

    pub fn open_stream(&mut self, addr: u8, sig: u16) -> Result<Receiver<Vec<u8>>, Error> {
        self._open_stream(addr, sig, None)
    }

    pub fn open_stream_enc(&mut self, addr: u8, sig: u16) -> Result<Receiver<Vec<u8>>, Error> {
        let key = self._find_enc_session(addr)?.key;
        self._open_stream(addr, sig, Some(&key))
    }

    fn _open_stream(&mut self, addr: u8, sig: u16, enc_key: Option<&[u8]>) -> Result<Receiver<Vec<u8>>, Error> {
        self._request(addr, sig, None, PacketType::StreamOpen, enc_key, None)?;
        let packet_rx = self.packet_rx.take().unwrap();
        let (tx_stream_ctl, rx_stream_ctl) = channel::<StreamCtl>();
        let (stream_data_tx, stream_data_rx) = channel::<Vec<u8>>();
        let enc_key_clone = match enc_key {
            Some(v) => Some(v.to_vec()),
            None => None,
        };
        let stream_th = thread::spawn(move || _stream_thread(
            rx_stream_ctl, packet_rx, addr, sig, enc_key_clone, stream_data_tx));
        self.stream_ctl = Some((stream_th, tx_stream_ctl));
        Ok(stream_data_rx)
    }

    pub fn close_stream(&mut self) -> Result<(), Error> {
        match self.stream_ctl.take() {
            Some((stream_th, stream_ctl_tx)) => {
                stream_ctl_tx.send(StreamCtl::Close).unwrap();
                self.packet_rx = Some(stream_th.join().unwrap());
            },
            None => (),
        }
        let start = time::Instant::now();
        let mut tl_stream_data = start;
        loop {
            self._request_no_answ(BROADCAST_ADDR, 0, None, PacketType::StreamClose, None)?;
            thread::sleep(STREAM_CLOSE_SEND_PERIOD);
            if let Ok(result) = self.packet_rx.as_mut().unwrap().try_recv() {
                if let Ok(packet) = result {
                    if packet.ptype == PacketType::StreamData {
                        tl_stream_data = time::Instant::now();
                    }
                }
            }

            if start.elapsed() > self.stream_close_timeout {
                break Err(Error::Response(ResponseError::Timeout(self.stream_close_timeout)));
            }
            if tl_stream_data.elapsed() >= self.min_stream_close_wait {
                break Ok(());
            }
        }
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    fn _find_enc_session<'a>(&'a self, addr: u8) -> Result<&'a EncSession, Error> {
        for s in &self.enc_sessions {
            if s.addr == addr {
                return Ok(s);
            }
        }
        Err(Error::Lib(LibError::EncSessionNotFound(addr)))
    }

    fn _find_enc_session_mut<'a>(&'a mut self, addr: u8) -> Result<&'a mut EncSession, Error> {
        for s in &mut self.enc_sessions {
            if s.addr == addr {
                return Ok(s);
            }
        }
        Err(Error::Lib(LibError::EncSessionNotFound(addr)))
    }

    fn _request(&mut self, addr: u8, sig: u16, data: Option<&[u8]>,
        ptype: PacketType, enc_key: Option<&[u8]>, timeout: Option<Duration>) -> Result<Vec<u8>, Error>
    {
        if self.stream_ctl.is_some() {
            return Err(Error::Lib(LibError::OperationNotPermittedWhileStreamIsOpen(ptype.into())));
        }
        if addr == BROADCAST_ADDR {
            return Err(Error::Lib(LibError::TryRequestWithBroadcast(ptype)));
        }

        let request = Packet::new(addr, Direction::Request, ptype, sig, data, enc_key)?;
        let timeout_real = if let Some(timeout) = timeout {
            timeout
        } else {
            self.timeout
        };

        self._flush_receive_thread()?;
        self._send_packet(&request)?;
        let mut answer = _receive_packet(self.packet_rx.as_mut().unwrap(), timeout_real)?;
        if answer.addr != request.addr {
            return Err(Error::Response(ResponseError::AddrMismatch { request: request.addr, answer: answer.addr}));
        }
        if answer.is_enc != request.is_enc {
            return Err(Error::Response(ResponseError::IsEncMismatch {request: request.is_enc, answer: answer.is_enc}));
        }
        if answer.dir != Direction::Answer {
            return Err(Error::Response(ResponseError::NotAnswerDirection));
        }

        if answer.ptype != PacketType::Err && answer.ptype != request.ptype {
            return Err(Error::Response(ResponseError::PacketTypeMismatch {
                request: request.ptype, answer: answer.ptype}));
        }

        if let Some(enc_key) = enc_key {
            answer.decrypt(enc_key)?;
        }

        if answer.ptype == PacketType::Err {
            return Err(Error::Response(ResponseError::ErrorAnswer(
                ErrorAnswer::from_answer(&answer.data, addr, ptype, sig)?)));
        }

        Ok(answer.data)
    }

    fn _request_no_answ(&mut self, addr: u8, sig: u16, data: Option<&[u8]>, ptype: PacketType, enc_key: Option<&[u8]>)
        -> Result<(), Error>
    {
        if addr == BROADCAST_ADDR && !BROADCAST_ALLOWED_PD_TYPES.contains(&ptype) {
            return Err(Error::Lib(LibError::NotAllowedPacketTypeForBroadcast(ptype)));
        }

        let request = Packet::new(addr, Direction::Request, ptype, sig, data, enc_key)?;

        self._send_packet(&request)?;

        Ok(())
    }

    fn _send_packet(&mut self, packet: &Packet) -> Result<(), Error> {
        let mut ios = self.io_stream.lock().unwrap();
        let packet_raw = packet.serialize()?;
        let frame = framer7b::encode(&packet_raw);
        ios.write_all(&frame)?;
        trace!("_send_packet: {packet:?} packet_raw={:?}", packet_raw);
        Ok(())
    }

    fn _flush_receive_thread(&mut self) -> Result<(), Error> {
        if self.stream_ctl.is_some() {
            return Err(Error::Lib(LibError::OperationNotPermittedWhileStreamIsOpen(Operation::FlushReceiveThread)));
        }
        loop {
            match self.packet_rx.as_mut().unwrap().try_recv() {
                Ok(result) => trace!("_flush_receive_thread: flush received result: {:?}", result),
                Err(_) => break,
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests;
