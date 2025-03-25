use std::{collections::BTreeMap, io};

use thiserror::Error;
use tokio::io::AsyncReadExt;

#[derive(Error, Debug)]
pub enum PacketBufferOpError {
    #[error("data store disconnected")]
    Io(#[from] io::Error),
    #[error("End of buffer: `{0}`")]
    BufferEnd(&'static str),
}

pub type Result<T> = std::result::Result<T, PacketBufferOpError>;

pub trait PacketBuffer {
    async fn read(&mut self) -> Result<u8>;
    async fn get(&mut self, pos: usize) -> Result<u8>;
    async fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;
    fn write(&mut self, val: u8) -> Result<()>;
    fn set(&mut self, pos: usize, val: u8) -> Result<()>;
    fn pos(&self) -> usize;
    fn seek(&mut self, pos: usize) -> Result<()>;
    fn step(&mut self, steps: usize) -> Result<()>;
    fn find_label(&self, label: &str) -> Option<usize>;
    fn save_label(&mut self, label: &str, pos: usize);

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        let split_str = qname.split('.').collect::<Vec<&str>>();

        let mut jump_performed = false;
        for (i, label) in split_str.iter().enumerate() {
            let search_lbl = split_str[i..split_str.len()].join(".");
            if let Some(prev_pos) = self.find_label(&search_lbl) {
                let jump_inst = (prev_pos as u16) | 0xC000;
                self.write_u16(jump_inst)?;
                jump_performed = true;

                break;
            }

            let pos = self.pos();
            self.save_label(&search_lbl, pos);

            let len = label.len();
            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        if !jump_performed {
            self.write_u8(0)?;
        }

        Ok(())
    }

    async fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read().await? as u16) << 8) | (self.read().await? as u16);

        Ok(res)
    }

    async fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read().await? as u32) << 24)
            | ((self.read().await? as u32) << 16)
            | ((self.read().await? as u32) << 8)
            | ((self.read().await? as u32) << 0);

        Ok(res)
    }

    async fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delim = "";
        loop {
            let len = self.get(pos).await?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) > 0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1).await? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize).await?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct VectorPacketBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize,
    pub label_lookup: BTreeMap<String, usize>,
}

impl VectorPacketBuffer {
    pub fn new() -> VectorPacketBuffer {
        VectorPacketBuffer {
            buffer: Vec::new(),
            pos: 0,
            label_lookup: BTreeMap::new(),
        }
    }
}

impl PacketBuffer for VectorPacketBuffer {
    fn find_label(&self, label: &str) -> Option<usize> {
        self.label_lookup.get(label).cloned()
    }

    fn save_label(&mut self, label: &str, pos: usize) {
        self.label_lookup.insert(label.to_string(), pos);
    }

    async fn read(&mut self) -> Result<u8> {
        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    async fn get(&mut self, pos: usize) -> Result<u8> {
        Ok(self.buffer[pos])
    }

    async fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        Ok(&self.buffer[start..start + len as usize])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        self.buffer.push(val);
        self.pos += 1;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buffer[pos] = val;

        Ok(())
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }
}

// udp
pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub async fn get_current_written_buffer(&mut self) -> Result<&[u8]> {
        let len = self.pos();
        Ok(self.get_range(0, len).await?)
    }
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        BytePacketBuffer::new()
    }
}

impl PacketBuffer for BytePacketBuffer {
    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, step: usize) -> Result<()> {
        self.pos += step;
        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    /// Read a single byte and move the position one step forward
    async fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(PacketBufferOpError::BufferEnd("read out of the index"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    async fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(PacketBufferOpError::BufferEnd("get out of the index"));
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    async fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(PacketBufferOpError::BufferEnd("Get range out of the index"));
        }
        Ok(&self.buf[start..start + len as usize])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(PacketBufferOpError::BufferEnd("write out of the index"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn find_label(&self, _label: &str) -> Option<usize> {
        None
    }

    fn save_label(&mut self, _label: &str, _pos: usize) {
        // todo!()
    }
}

// tcp
pub struct StreamPacketBuffer<'a, T>
where
    T: AsyncReadExt,
{
    pub stream: &'a mut T,
    pub buffer: Vec<u8>,
    pub pos: usize,
}

impl<'a, T> StreamPacketBuffer<'a, T>
where
    T: AsyncReadExt + 'a,
{
    pub fn new(stream: &mut T) -> StreamPacketBuffer<T> {
        StreamPacketBuffer {
            stream: stream,
            buffer: Vec::new(),
            pos: 0,
        }
    }
}

impl<'a, T> PacketBuffer for StreamPacketBuffer<'a, T>
where
    T: AsyncReadExt + 'a + Unpin,
{
    fn find_label(&self, _: &str) -> Option<usize> {
        None
    }

    fn save_label(&mut self, _: &str, _: usize) {
        unimplemented!();
    }

    async fn read(&mut self) -> Result<u8> {
        while self.pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read(&mut local_buffer).await?;
            self.buffer.push(local_buffer[0]);
        }

        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    async fn get(&mut self, pos: usize) -> Result<u8> {
        while pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read(&mut local_buffer).await?;
            self.buffer.push(local_buffer[0]);
        }

        Ok(self.buffer[pos])
    }

    async fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        while start + len > self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read(&mut local_buffer).await?;
            self.buffer.push(local_buffer[0]);
        }

        Ok(&self.buffer[start..start + len as usize])
    }

    fn write(&mut self, _: u8) -> Result<()> {
        unimplemented!();
    }

    fn set(&mut self, _: usize, _: u8) -> Result<()> {
        unimplemented!();
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }
}
