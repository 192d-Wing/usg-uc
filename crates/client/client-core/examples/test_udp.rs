use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    println!("Bound to: {}", socket.local_addr()?);

    let dest: SocketAddr = "76.8.29.198:5060".parse()?;

    let register = "REGISTER sip:sip.bulkvs.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKrusttest\r\n\
From: <sip:611956_test@sip.bulkvs.com>;tag=rusttag\r\n\
To: <sip:611956_test@sip.bulkvs.com>\r\n\
Call-ID: rusttest@localhost\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:611956_test@0.0.0.0:5060>\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n";

    println!("Sending REGISTER...");
    socket.send_to(register.as_bytes(), dest).await?;
    println!("Sent {} bytes", register.len());

    let mut buf = [0u8; 4096];
    println!("Waiting for response...");

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((n, src))) => {
            println!("Received {} bytes from {}", n, src);
            println!("Response:\n{}", String::from_utf8_lossy(&buf[..n]));
        }
        Ok(Err(e)) => println!("Receive error: {}", e),
        Err(_) => println!("Timeout waiting for response"),
    }

    Ok(())
}
