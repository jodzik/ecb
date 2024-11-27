const MARK_MASK: u8	= 0b10000000;
const BEGIN: u8	= 0b11010100;
const END: u8 = 0b10000001;
const FRAMING_BYTES_COUNT_IN_FRAME: usize = 2;


#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("Too small frame for decode.")]
    TooSmallFrame,
    #[error("Unexpected framing begin byte.")]
    UnexpectedBegin,
    #[error("Unknown framing(with mark) byte.")]
    UnknownFramingByte(u8),
    #[error("Buffer overflow.")]
    BufferOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Wait,
    Receive,
}

pub struct Framer7b {
    state: State,
    ptr: usize,
    buf: Vec<u8>,
}

/// Encode packet - add framing bytes, encode data - add ADD field, clear mark bits inside packet data.  
/// Return `frame` as Vec<u8>.
pub fn encode(packet: &[u8]) -> Vec<u8> {
    let ndata = packet.len();
    let ndata_add = if ndata % 7 == 0 {ndata / 7} else {ndata / 7 + 1};
	let idata_add = ndata;
    let mut frame = vec![0; ndata + ndata_add + FRAMING_BYTES_COUNT_IN_FRAME];
    let frame_size = frame.len();

    frame[0] = BEGIN;

	for i in 0..ndata {
        frame[i + 1] = packet[i];
        if frame[i + 1] & MARK_MASK > 0 {
			frame[1 + idata_add + i / 7] |= 1 << (i % 7);
			frame[i + 1] &= !MARK_MASK;
		}
	}

    frame[frame_size - 1] = END;

	return frame;
}

/// Decode data inside the same buffer.  
/// Put data without mark bytes.  
/// Return new data size.  
/// `data` must include only data bytes, without mark(framing) bytes.
fn _decode(data: &mut [u8]) -> Result<usize, Error> {
	let ndata = data.len();
    if ndata < 2 {
        return Err(Error::TooSmallFrame);
    }
    let ndata_add = if ndata % 8 == 0 {ndata / 8} else {ndata / 8 + 1};
	let ndata_result = ndata - ndata_add; // Without add bytes

	for i in 0..ndata_result {
		if (data[ndata_result + i / 7] & (1 << (i % 7))) > 0 {
			data[i] |= MARK_MASK;
		}
	}

	return Ok(ndata_result);
}

impl Framer7b {
    pub fn new(buf_size: usize) -> Self {
        Self {
            state: State::Wait,
            ptr: 0,
            buf: vec![0; buf_size],
        }
    }

    pub fn reset(&mut self) {
        self.state = State::Wait;
        self.ptr = 0;
    }

    pub fn push<'a>(&'a mut self, byte: u8) -> Result<Option<&'a [u8]>, Error> {
        let mut result: Option<&'a [u8]> = None;

        match self.state {
            State::Wait => if byte == BEGIN {
                self.reset();
                self.state = State::Receive;
            },
            State::Receive => if byte & MARK_MASK > 0 {
                // This is a framing byte, most likely END, anyway reset ptr.
                let ptr = self.ptr;
                self.reset();
                if byte == END {
                    // Try decode
                    let ndata = _decode(&mut self.buf[..ptr])?;
                    result = Some(&self.buf[..ndata]);
                } else if byte == BEGIN {
                    // This is an incorrect situation, but in order not to lose frame - set receive. 
                    self.state = State::Receive;
                    return Err(Error::UnexpectedBegin);
                } else {
                    return Err(Error::UnknownFramingByte(byte));
                }
            } else {
                // This is a data - push back.
                if self.ptr >= self.buf.len() {
                    // Buffer overflow.
                    self.reset();
                    return Err(Error::BufferOverflow);
                } else {
                    self.buf[self.ptr] = byte;
                    self.ptr += 1;
                }
            }
        }

        return Ok(result);
    }

    pub fn state(&self) -> State {self.state}
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_cycle() -> Result<(), Error> {
        const BUF_SIZE: usize = 256;
        const DATA_SIZE: usize = BUF_SIZE - BUF_SIZE / 7;

        let mut framer = Framer7b::new(BUF_SIZE);
        let mut data: [u8; DATA_SIZE] = [0; DATA_SIZE];

        for i in 0..DATA_SIZE {
            data[i] = i as u8;
        }

        let frame_to_send = encode(&data);

        assert_eq!(State::Wait, framer.state());
        for i in 0..frame_to_send.len() - 1 {
            let result = framer.push(frame_to_send[i])?;
            assert_eq!(None, result, "d={}", frame_to_send[i]);
            assert_eq!(State::Receive, framer.state());
        }

        {
            let result = framer.push(frame_to_send[frame_to_send.len() - 1])?;
            assert_eq!(Some(&data[..]), result);
        }
        assert_eq!(State::Wait, framer.state());
        Ok(())
    }
}
