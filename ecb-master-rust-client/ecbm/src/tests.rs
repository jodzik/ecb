use super::*;

struct IoMock<F>
    where F: Fn(&[u8]) -> Vec<u8>,
{
    read_series: Vec<Vec<u8>>,
    on_write: F,
}

impl<F> IoMock<F>
    where F: Fn(&[u8]) -> Vec<u8>,
{
    pub fn new(on_write: F) -> Self {
        IoMock {
            read_series: Vec::new(),
            on_write: on_write,
        }
    }

    pub fn add_read(&mut self, data: Vec<u8>) {
        self.read_series.push(data);
    }
}

impl<F> Read for IoMock<F>
    where F: Fn(&[u8]) -> Vec<u8>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_series.len() > 0 {
            let data = self.read_series.remove(0);
            buf[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""))
        }
    }
}

impl<F> Write for IoMock<F>
    where F: Fn(&[u8]) -> Vec<u8>,
{
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.write(buf)?;
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let for_read = (self.on_write)(buf);
        if for_read.len() > 0 {
            self.add_read(for_read);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn write() -> Result<(), Error> {
    const WRITE_DATA_SIZE: usize = 4;
    let io = IoMock::new(|buf| {
        let mut framer = framer7b::Framer7b::new(256);
        for i in 0..buf.len() - 1 {
            assert_eq!(framer.push(buf[i]), Ok(None));
        }
        let packet = framer.push(buf[buf.len()-1]).unwrap().unwrap();
        assert_eq!(packet.len(), SERVICE_DATA_SIZE + WRITE_DATA_SIZE);
        assert_eq!(packet[ADDR_INDEX], 1);
        assert_eq!(packet[PD_INDEX], 0x10);
        assert_eq!(u16::from_le_bytes(packet[SIGNAL_INDEX..SIGNAL_INDEX+2].try_into().unwrap()), 2);
        assert_eq!(packet[NFILL_INDEX], 0);

        let mut answ = vec![0;SERVICE_DATA_SIZE];
        answ[ADDR_INDEX] = 1;
        answ[PD_INDEX] = 0x00;
        let sig_bytes = (2 as u16).to_le_bytes();
        answ[SIGNAL_INDEX..SIGNAL_INDEX+2].copy_from_slice(&sig_bytes);
        answ[NFILL_INDEX] = 0;
        let crc = crc::crc32(&answ[..answ.len()-CRC32_SIZE]);
        let crc_bytes = crc.to_le_bytes();
        let crc_pos = answ.len()-CRC32_SIZE;
        answ[crc_pos..].copy_from_slice(&crc_bytes);
        framer7b::encode(&answ)
    });

    let mut ecbm = Ecbm::new(io);
    ecbm.write(1, 2, &[0, 1, 2, 3], None)?;
    Ok(())
}

#[test]
fn write_timeout() {
    const TIMEOUT: Duration = Duration::from_millis(100);
    let io = IoMock::new(|_| {Vec::new()});

    let mut ecbm = Ecbm::new(io);
    let result = ecbm.write(1, 2, &[0, 1, 2, 3], Some(TIMEOUT));
    assert_eq!(result, Err(Error::Response(ResponseError::Timeout(TIMEOUT))));
}

#[test]
fn write_bad_frame_skip_non_fatal_unexpected_begin() {
    let io = IoMock::new(|_| {vec![0xD4, 0, 1, 0xD4, 0, 0, 0x81]});

    let mut ecbm = Ecbm::new(io);
    let result = ecbm.write(1, 2, &[0, 1, 2, 3], None);
    assert_eq!(result, Err(Error::Response(ResponseError::NoServiceData(1))));
}

#[test]
fn write_bad_frame_skip_non_fatal_unknown_framing_byte() {
    let io = IoMock::new(|_| {vec![0xFF, 0xFF, 1, 0xD4, 0, 0, 0x81]});

    let mut ecbm = Ecbm::new(io);
    let result = ecbm.write(1, 2, &[0, 1, 2, 3], None);
    assert_eq!(result, Err(Error::Response(ResponseError::NoServiceData(1))));
}

#[test]
fn write_bad_frame_too_small() {
    let io = IoMock::new(|_| {vec![0xD4, 0, 0x81]});

    let mut ecbm = Ecbm::new(io);
    let result = ecbm.write(1, 2, &[0, 1, 2, 3], None);
    assert_eq!(result, Err(Error::Response(ResponseError::Framer7bError(framer7b::Error::TooSmallFrame))));
}

#[test]
fn write_bad_answer_crc() {
    const WRITE_DATA_SIZE: usize = 4;
    let io = IoMock::new(|buf| {
        let mut framer = framer7b::Framer7b::new(256);
        for i in 0..buf.len() - 1 {
            assert_eq!(framer.push(buf[i]), Ok(None));
        }
        let packet = framer.push(buf[buf.len()-1]).unwrap().unwrap();
        assert_eq!(packet.len(), SERVICE_DATA_SIZE + WRITE_DATA_SIZE);
        assert_eq!(packet[ADDR_INDEX], 1);
        assert_eq!(packet[PD_INDEX], 0x10);
        assert_eq!(u16::from_le_bytes(packet[SIGNAL_INDEX..SIGNAL_INDEX+2].try_into().unwrap()), 2);
        assert_eq!(packet[NFILL_INDEX], 0);

        let mut answ = vec![0;SERVICE_DATA_SIZE];
        answ[ADDR_INDEX] = 1;
        answ[PD_INDEX] = 0x00;
        let sig_bytes = (2 as u16).to_le_bytes();
        answ[SIGNAL_INDEX..SIGNAL_INDEX+2].copy_from_slice(&sig_bytes);
        answ[NFILL_INDEX] = 0;
        let crc_bytes = [0, 0, 0, 0];
        let crc_pos = answ.len()-CRC32_SIZE;
        answ[crc_pos..].copy_from_slice(&crc_bytes);
        framer7b::encode(&answ)
    });

    let mut ecbm = Ecbm::new(io);
    let result = ecbm.write(1, 2, &[0, 1, 2, 3], None);
    assert_eq!(result, Err(Error::Response(ResponseError::CrcMismatch)));
}

#[test]
fn write_bad_answer_addr() {
    const WRITE_DATA_SIZE: usize = 4;
    let io = IoMock::new(|buf| {
        let mut framer = framer7b::Framer7b::new(256);
        for i in 0..buf.len() - 1 {
            assert_eq!(framer.push(buf[i]), Ok(None));
        }
        let packet = framer.push(buf[buf.len()-1]).unwrap().unwrap();
        assert_eq!(packet.len(), SERVICE_DATA_SIZE + WRITE_DATA_SIZE);
        assert_eq!(packet[ADDR_INDEX], 1);
        assert_eq!(packet[PD_INDEX], 0x10);
        assert_eq!(u16::from_le_bytes(packet[SIGNAL_INDEX..SIGNAL_INDEX+2].try_into().unwrap()), 2);
        assert_eq!(packet[NFILL_INDEX], 0);

        let mut answ = vec![0;SERVICE_DATA_SIZE];
        answ[ADDR_INDEX] = 2;
        answ[PD_INDEX] = 0x00;
        let sig_bytes = (2 as u16).to_le_bytes();
        answ[SIGNAL_INDEX..SIGNAL_INDEX+2].copy_from_slice(&sig_bytes);
        answ[NFILL_INDEX] = 0;
        let crc = crc::crc32(&answ[..answ.len()-CRC32_SIZE]);
        let crc_bytes = crc.to_le_bytes();
        let crc_pos = answ.len()-CRC32_SIZE;
        answ[crc_pos..].copy_from_slice(&crc_bytes);
        framer7b::encode(&answ)
    });

    let mut ecbm = Ecbm::new(io);
    let result = ecbm.write(1, 2, &[0, 1, 2, 3], None);
    assert_eq!(result, Err(Error::Response(ResponseError::AddrMismatch { request: 1, answer: 2 })));
}

#[test]
fn write_bad_answer_pd() {
    const WRITE_DATA_SIZE: usize = 4;
    let io = IoMock::new(|buf| {
        let mut framer = framer7b::Framer7b::new(256);
        for i in 0..buf.len() - 1 {
            assert_eq!(framer.push(buf[i]), Ok(None));
        }
        let packet = framer.push(buf[buf.len()-1]).unwrap().unwrap();
        assert_eq!(packet.len(), SERVICE_DATA_SIZE + WRITE_DATA_SIZE);
        assert_eq!(packet[ADDR_INDEX], 1);
        assert_eq!(packet[PD_INDEX], 0x10);
        assert_eq!(u16::from_le_bytes(packet[SIGNAL_INDEX..SIGNAL_INDEX+2].try_into().unwrap()), 2);
        assert_eq!(packet[NFILL_INDEX], 0);

        let mut answ = vec![0;SERVICE_DATA_SIZE];
        answ[ADDR_INDEX] = 1;
        answ[PD_INDEX] = 0b1110;
        let sig_bytes = (2 as u16).to_le_bytes();
        answ[SIGNAL_INDEX..SIGNAL_INDEX+2].copy_from_slice(&sig_bytes);
        answ[NFILL_INDEX] = 0;
        let crc = crc::crc32(&answ[..answ.len()-CRC32_SIZE]);
        let crc_bytes = crc.to_le_bytes();
        let crc_pos = answ.len()-CRC32_SIZE;
        answ[crc_pos..].copy_from_slice(&crc_bytes);
        framer7b::encode(&answ)
    });

    let mut ecbm = Ecbm::new(io);
    let result = ecbm.write(1, 2, &[0, 1, 2, 3], None);
    assert_eq!(result, Err(Error::Response(ResponseError::UnknownPacketType(0b1110))));
}
