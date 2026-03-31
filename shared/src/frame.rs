use crate::constants::*;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

pub async fn send_frame<S>(
    stream: &mut S,
    msg_type: u8,
    payload: &[u8],
) -> Result<(), std::io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    let length = (1 + payload.len()) as u32;
    let length_bytes = length.to_be_bytes();
    let mut buf = Vec::new();
    buf.extend_from_slice(&length_bytes);
    buf.push(msg_type);
    buf.extend_from_slice(payload);
    stream.write_all(&buf).await?;
    Ok(())
}

pub async fn recv_frame<S>(stream: &mut S) -> Result<(u8, Vec<u8>), std::io::Error>
where
    S: AsyncReadExt + Unpin,
{
    let mut length_buf = [0u8; 4];
    stream.read_exact(&mut length_buf).await?;
    let length = u32::from_be_bytes(length_buf) as usize;
    if !(1..=MAX_FRAME_SIZE).contains(&length) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Frame length out of bounds",
        ));
    }
    let mut buf = vec![0u8; length];
    stream.read_exact(&mut buf).await?;
    Ok((buf[0], buf[1..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_recv_basic() {
        // happy path
        let (mut client, mut server) = tokio::io::duplex(1024);
        send_frame(&mut server, 0x01, b"hello").await.unwrap();
        let (msg_type, payload) = recv_frame(&mut client).await.unwrap();

        assert_eq!(msg_type, 0x01);
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn test_recv_rejects_zero_length() {
        // malformed frame
        let (mut client, mut server) = tokio::io::duplex(1024);
        let bad_length: u32 = 0;
        client.write_all(&bad_length.to_be_bytes()).await.unwrap();
        let result = recv_frame(&mut server).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_recv_rejects_oversized_frame() {
        // MAX_FRAME_SIZE exceeded
        let (mut client, mut server) = tokio::io::duplex(1024);
        let bad_length: u32 = (MAX_FRAME_SIZE + 1) as u32;
        client.write_all(&bad_length.to_be_bytes()).await.unwrap();
        let result = recv_frame(&mut server).await;
        assert!(result.is_err());
    }
}
