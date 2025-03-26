use dns::handle_query;
use std::net::UdpSocket;

mod dns;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, world!");
    println!("Hello, world!");

    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match handle_query(&socket).await {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }

    // Ok(())
}
