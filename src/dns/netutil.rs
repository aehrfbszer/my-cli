use std::io::Result;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub async fn read_packet_length(stream: &mut TcpStream) -> Result<u16> {
    let mut len_buffer = [0; 2];
    stream.read(&mut len_buffer).await?;

    Ok(((len_buffer[0] as u16) << 8) | (len_buffer[1] as u16))
}

pub async fn write_packet_length(stream: &mut TcpStream, len: usize) -> Result<()> {
    let mut len_buffer = [0; 2];
    len_buffer[0] = (len >> 8) as u8;
    len_buffer[1] = (len & 0xFF) as u8;

    stream.write(&len_buffer).await?;

    Ok(())
}
