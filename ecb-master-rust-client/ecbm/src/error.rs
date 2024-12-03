use std::time::Duration;

use num_derive::FromPrimitive;

use crate::PacketType;


const ANSW_ERR_USER_APP: u8 = 1;
const ANSW_ERR_NO_SIG: u8 = 2;
const ANSW_ERR_NO_OPERATION: u8 = 3;
const ANSW_ERR_ENC_REQUIRED: u8 = 4;
const ANSW_ERR_AUTH_REQUIRED: u8 = 5;
const ANSW_ERR_NO_ENC_SESSION: u8 = 6;
const ANSW_ERR_INTERNAL: u8 = 7;
const ANSW_ERR_INCORRECT_SIGN: u8 = 8;
const ANSW_ERR_ENC_NOT_SUPPORTED: u8 = 9;


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
    #[error("Encryption session not started for device at addr {0}")]
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
    pub fn from_answer(answer: &[u8], addr: u8, ptype: PacketType, sig: u16) -> Result<Self, Error> {
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
                let internal_err_code = u32::from_be_bytes(answer[1..1+size_of::<u32>()].try_into().unwrap());
                Ok(Self::Internal(internal_err_code.into()))
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
    #[error("Answer was received, but signal is mismatch: request sig - {request}, answer sig - {answer}.")]
    SigMismatch {
        request: u16,
        answer: u16,
    },
    #[error("Answer was received, but seq is mismatch: request seq - {request}, answer seq - {answer}.")]
    SeqMismatch {
        request: u8,
        answer: u8,
    },
    #[error("Answer was received, but has encrypted data, but encryption key not given.")]
    UnexpectedEncAnswer,
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
    #[error("Request was success, but application data in answer invalid: {0}")]
    InvalidAppData(String),
    #[error("Device success reset, but expected than 'ECB Boot' would be running, but running '{0}'")]
    NoBootloader(String),
    #[error("Given test phrase invalid - this may mean an incorrect firmware key.")]
    TestPhraseInvalid,
    #[error("Firmware was written to nvm, but checksum of it is a mismatch with origin.")]
    WrittenFirmwareCorrupted,
}

impl From<raiden::Error> for ResponseError {
    fn from(value: raiden::Error) -> Self {
        Self::RaidenError(value)
    }
}

impl ResponseError {
    pub fn is_bus_error(&self) -> bool {
        match &self {
            Self::CrcMismatch => true,
            Self::Framer7bError(_) => true,
            Self::Timeout(_) => true,
            _ => false,
        }
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
    #[error("Incorrect write block size for write firmware({0}): value must be multiple of raiden::BLOCK_SIZE.")]
    IncorrectWriteBlockSize(usize),
    #[error("Serial is invalid: {0}.")]
    InvalidSerial(String),
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

    pub fn is_user_app_err(&self) -> bool {
        if let Error::Response(resp_err) = &self {
            if let ResponseError::ErrorAnswer(err_answ) = resp_err {
                if let ErrorAnswer::UserAppError { .. } = err_answ {
                    return true;
                }
            }
        }

        false
    }

    pub fn user_app_err(&self) -> Option<u32> {
        if let Error::Response(resp_err) = &self {
            if let ResponseError::ErrorAnswer(err_answ) = resp_err {
                if let ErrorAnswer::UserAppError { err_code, .. } = err_answ {
                    return Some(*err_code);
                }
            }
        }

        None
    }

    pub fn is_user_app_err_code(&self, code: u32) -> bool {
        if let Error::Response(resp_err) = &self {
            if let ResponseError::ErrorAnswer(err_answ) = resp_err {
                if let ErrorAnswer::UserAppError { err_code, .. } = err_answ {
                    return *err_code == code;
                }
            }
        }

        false
    }

    pub fn is_seq_mismatch(&self) -> bool {
        if let Error::Response(resp_err) = &self {
            if let ResponseError::SeqMismatch { .. } = resp_err {
                return true;
            }
        }

        false
    }
}
