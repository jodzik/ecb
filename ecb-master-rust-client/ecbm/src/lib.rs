pub mod app_lvl;
pub mod error;
pub mod packet;

use error::*;
use packet::*;

use std::{fmt::Debug, io::{Read, Write}, sync::{mpsc::{channel, Receiver, SendError, Sender}, Arc, Mutex}, thread::{self, JoinHandle}, time::{self, Duration}};
use framer7b::Framer7b;
use log::{debug, trace};


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
const DEFAULT_N_REQUEST_ATTEMPT: u8 = 3;
const FRAMER_BUF_SIZE: usize = MAX_PACKET_SIZE * (MAX_PACKET_SIZE / 7) + 1;
const RECEIVE_THREAD_START_DURATION: Duration = Duration::from_millis(100);


type PacketRx = Receiver<Result<Packet, Error>>;


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
                            framer7b::Error::UnexpectedBegin => trace!("_receive_thread_process: UnexpectedBegin."),
                            framer7b::Error::UnknownFramingByte(b) => trace!("_receive_thread_process: UnknownFramingByte({b})."),
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

    let result = loop {
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
    };
    match &result {
        Ok(v) => trace!("Packet received: {v:?}."),
        Err(e) => trace!("Fail to receive packet: {e:?}."),
    }
    result
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
    n_request_attempts: u8,
    t_create: time::Instant,
    seq: u8,
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
            n_request_attempts: DEFAULT_N_REQUEST_ATTEMPT,
            t_create: time::Instant::now(),
            seq: 0,
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

    pub fn set_request_attempts(&mut self, n_request_attempts: u8) {
        self.n_request_attempts = n_request_attempts;
    }

    pub fn open_enc_session(&mut self, addr: u8, enc_key: &[u8]) -> Result<(), Error> {
        let session_key_enc = self._request_with_tries(addr, 0, None, PacketType::EncOpen, None, Some(self.timeout))?;
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
        self._request_with_tries(addr, sig, None, PacketType::Read, None, timeout)
    }

    pub fn read_enc(&mut self, addr: u8, sig: u16, timeout: Option<Duration>) -> Result<Vec<u8>, Error> {
        let key = self._find_enc_session(addr)?.key.clone();
        self._request_with_tries(addr, sig, None, PacketType::Read, Some(&key), timeout)
    }

    pub fn write(&mut self, addr: u8, sig: u16, data: &[u8], timeout: Option<Duration>) -> Result<(), Error> {
        self._request_with_tries(addr, sig, Some(data), PacketType::Write, None, timeout)?;
        Ok(())
    }

    pub fn write_enc(&mut self, addr: u8, sig: u16, data: &[u8], timeout: Option<Duration>) -> Result<(), Error> {
        let key = self._find_enc_session(addr)?.key.clone();
        self._request_with_tries(addr, sig, Some(data), PacketType::Write, Some(&key), timeout)?;
        Ok(())
    }

    pub fn write_auth(&mut self, addr: u8, sig: u16, data: &[u8], timeout: Option<Duration>) -> Result<(), Error> {
        let key = self._find_enc_session(addr)?.key.clone();
        let sign = self._request_with_tries(addr, sig, Some(data), PacketType::WriteAuthReq, None, None)?;
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

        self._request_with_tries(addr, sig, Some(&sign_data), PacketType::WriteWithAuth, Some(&key), timeout)?;

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
        self._request_with_tries(addr, sig, None, PacketType::StreamOpen, enc_key, None)?;
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

    fn _request_with_tries(&mut self, addr: u8, sig: u16, data: Option<&[u8]>,
        ptype: PacketType, enc_key: Option<&[u8]>, timeout: Option<Duration>) -> Result<Vec<u8>, Error>
    {
        let mut last_err = None;
        for i in 0..self.n_request_attempts {
            match self._request(addr, sig, data, ptype, enc_key, timeout) {
                Ok(v) => return Ok(v),
                Err(err) => match &err {
                    Error::Lib(_) => return Err(err),
                    Error::Response(resp_err) => if !resp_err.is_bus_error() {
                        return Err(err);
                    } else {
                        debug!("Request(addr={addr} sig={sig}) attempt {i} failed: {err:?}.");
                        last_err = Some(err);
                    }
                },
            }
        }
        Err(last_err.unwrap())
    }

    fn _request(&mut self, addr: u8, sig: u16, data: Option<&[u8]>,
        ptype: PacketType, enc_key: Option<&[u8]>, timeout: Option<Duration>) -> Result<Vec<u8>, Error>
    {
        trace!("_request: addr={addr} sig={sig}.");
        if self.stream_ctl.is_some() {
            return Err(Error::Lib(LibError::OperationNotPermittedWhileStreamIsOpen(ptype.into())));
        }
        if addr == BROADCAST_ADDR {
            return Err(Error::Lib(LibError::TryRequestWithBroadcast(ptype)));
        }

        let request = Packet::new(addr, Direction::Request, ptype, sig, self.seq, data, enc_key)?;
        self._increment_seq();
        let timeout_real = if let Some(timeout) = timeout {
            timeout
        } else {
            self.timeout
        };

        self._flush_receive_thread()?;
        self._send_packet(&request)?;
        let mut answer = _receive_packet(self.packet_rx.as_mut().unwrap(), timeout_real)?;
        
        if answer.dir != Direction::Answer {
            return Err(Error::Response(ResponseError::NotAnswerDirection));
        }
        if answer.addr != request.addr {
            return Err(Error::Response(ResponseError::AddrMismatch { request: request.addr, answer: answer.addr}));
        }
        if answer.sig != request.sig {
            return Err(Error::Response(ResponseError::SigMismatch { request: request.sig, answer: answer.sig}));
        }
        if answer.seq != request.seq {
            return Err(Error::Response(ResponseError::SeqMismatch { request: request.seq, answer: answer.seq}));
        }

        let ptype_mismatch = if request.ptype.is_write_type() && answer.ptype.is_write_type() {
            false
        } else {
            answer.ptype != request.ptype
        };
        if answer.ptype != PacketType::Err && ptype_mismatch {
            return Err(Error::Response(ResponseError::PacketTypeMismatch {
                request: request.ptype, answer: answer.ptype}));
        }

        if answer.is_enc && !answer.data.is_empty() {
            if let Some(enc_key) = enc_key {
                answer.decrypt(enc_key)?;
            } else {
                return Err(Error::Response(ResponseError::UnexpectedEncAnswer));
            }            
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
        trace!("_request_no_answ: addr={addr} sig={sig}.");
        if addr == BROADCAST_ADDR && !BROADCAST_ALLOWED_PD_TYPES.contains(&ptype) {
            return Err(Error::Lib(LibError::NotAllowedPacketTypeForBroadcast(ptype)));
        }

        let request = Packet::new(addr, Direction::Request, ptype, sig, 0, data, enc_key)?;

        self._send_packet(&request)?;

        Ok(())
    }

    fn _send_packet(&mut self, packet: &Packet) -> Result<(), Error> {
        let mut ios = self.io_stream.lock().unwrap();
        let packet_raw = packet.serialize()?;
        let frame = framer7b::encode(&packet_raw);
        ios.write_all(&frame)?;
        trace!("_send_packet: {packet:?}.");
        Ok(())
    }

    fn _flush_receive_thread(&mut self) -> Result<(), Error> {
        let te_create = self.t_create.elapsed();
        if te_create < RECEIVE_THREAD_START_DURATION {
            thread::sleep(RECEIVE_THREAD_START_DURATION - te_create);
        }
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

    fn _increment_seq(&mut self) {
        self.seq = self.seq.overflowing_add(1).0
    }
}


#[cfg(test)]
mod tests;
