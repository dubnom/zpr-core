//! Loopback DNS stub that forwards queries to a bootstrapped ZPR DNS service.

use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::config::DnsProxyConfig;

const MAX_CONCURRENT_QUERIES: usize = 64;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;

/// Start the optional local stub. It only listens on loopback and always forwards
/// upstream over TCP to the explicitly configured ZPR address.
pub async fn launch(config: DnsProxyConfig, tun_interface: String) {
    if let Err(error) = run(config, tun_interface).await {
        error!("DNS stub stopped: {error}");
    }
}

async fn run(config: DnsProxyConfig, tun_interface: String) -> io::Result<()> {
    let udp = Arc::new(UdpSocket::bind(config.listen).await?);
    let tcp = TcpListener::bind(config.listen).await?;
    serve(config.server, Arc::from(tun_interface), udp, tcp).await
}

async fn serve(
    server: SocketAddr,
    tun_interface: Arc<str>,
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));
    let mut workers = JoinSet::new();

    info!(
        listen = %tcp.local_addr()?,
        upstream = %server,
        "starting loopback DNS stub"
    );

    loop {
        tokio::select! {
            received = tcp.accept() => {
                let (stream, peer) = received?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!(%peer, "dropping DNS TCP connection: query limit reached");
                    drop(stream);
                    continue;
                };
                let tun_interface = tun_interface.clone();
                workers.spawn_local(async move {
                    let _permit = permit;
                    if let Err(error) = serve_tcp_client(stream, server, &tun_interface).await {
                        debug!(%peer, %error, "DNS TCP client ended");
                    }
                });
            }
            received = recv_udp(&udp) => {
                let (query, peer) = received?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!(%peer, "dropping DNS UDP query: query limit reached");
                    continue;
                };
                let udp = udp.clone();
                let tun_interface = tun_interface.clone();
                workers.spawn_local(async move {
                    let _permit = permit;
                    match timeout(
                        QUERY_TIMEOUT,
                        forward_query(server, &tun_interface, &query),
                    )
                    .await
                    {
                        Ok(Ok(response)) => {
                            if let Err(error) = udp.send_to(&response, peer).await {
                                debug!(%peer, %error, "failed to return DNS UDP response");
                            }
                        }
                        Ok(Err(error)) => debug!(%peer, %error, "DNS UDP query failed upstream"),
                        Err(_) => debug!(%peer, "DNS UDP query timed out upstream"),
                    }
                });
            }
            Some(result) = workers.join_next(), if !workers.is_empty() => {
                if let Err(error) = result {
                    error!(%error, "DNS stub worker panicked");
                }
            }
        }
    }
}

async fn recv_udp(socket: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut packet = vec![0; MAX_DNS_MESSAGE_SIZE];
    let (size, peer) = socket.recv_from(&mut packet).await?;
    packet.truncate(size);
    Ok((packet, peer))
}

async fn serve_tcp_client(
    mut client: TcpStream,
    upstream: SocketAddr,
    tun_interface: &str,
) -> io::Result<()> {
    loop {
        let mut length = [0; 2];
        match timeout(QUERY_TIMEOUT, client.read_exact(&mut length)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DNS client read timed out",
                ));
            }
        }
        let query_length = usize::from(u16::from_be_bytes(length));
        if query_length < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS query is shorter than its header",
            ));
        }
        let mut query = vec![0; query_length];
        timeout(QUERY_TIMEOUT, client.read_exact(&mut query))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS client payload read timed out")
            })??;
        let response = timeout(
            QUERY_TIMEOUT,
            forward_query(upstream, tun_interface, &query),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream query timed out"))??;
        client
            .write_all(&(response.len() as u16).to_be_bytes())
            .await?;
        client.write_all(&response).await?;
    }
}

async fn forward_query(
    upstream: SocketAddr,
    tun_interface: &str,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    if query.len() < 12 || query.len() > MAX_DNS_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS query length",
        ));
    }
    let mut stream = connect_via_tun(upstream, tun_interface).await?;
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(query).await?;
    let mut length = [0; 2];
    stream.read_exact(&mut length).await?;
    let response_length = usize::from(u16::from_be_bytes(length));
    if response_length < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response is shorter than its header",
        ));
    }
    let mut response = vec![0; response_length];
    stream.read_exact(&mut response).await?;
    if response[..2] != query[..2] || response[2] & 0x80 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response does not match query",
        ));
    }
    Ok(response)
}

async fn connect_via_tun(upstream: SocketAddr, tun_interface: &str) -> io::Result<TcpStream> {
    let interface_name = CString::new(tun_interface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN interface name contains NUL",
        )
    })?;
    // SAFETY: interface_name is NUL-terminated and lives through the call.
    let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
    let interface_index = NonZeroU32::new(interface_index).ok_or_else(io::Error::last_os_error)?;
    let socket = if upstream.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    bind_to_interface(
        &socket,
        &interface_name,
        interface_index.get(),
        upstream.is_ipv4(),
    )?;
    socket.connect(upstream).await
}

#[cfg(target_os = "linux")]
fn bind_to_interface(
    socket: &TcpSocket,
    interface_name: &CString,
    _interface_index: u32,
    _is_ipv4: bool,
) -> io::Result<()> {
    // SAFETY: the descriptor is live and interface_name is NUL-terminated.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface_name.as_ptr().cast(),
            interface_name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn bind_to_interface(
    socket: &TcpSocket,
    _interface_name: &CString,
    interface_index: u32,
    is_ipv4: bool,
) -> io::Result<()> {
    let level = if is_ipv4 {
        libc::IPPROTO_IP
    } else {
        libc::IPPROTO_IPV6
    };
    let option = if is_ipv4 {
        libc::IP_BOUND_IF
    } else {
        libc::IPV6_BOUND_IF
    };
    let interface_index = interface_index as libc::c_uint;
    // SAFETY: the descriptor is live and interface_index remains valid for the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&interface_index as *const libc::c_uint).cast(),
            std::mem::size_of_val(&interface_index) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwards_a_dns_message_over_tcp() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut expected_response = query.to_vec();
        expected_response[2] |= 0x80;
        let response_for_server = expected_response.clone();

        let upstream = tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).await.unwrap();
            let mut received = vec![0; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, query);
            stream
                .write_all(&(response_for_server.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response_for_server).await.unwrap();
        });

        let response = forward_query(server_addr, loopback_interface(), &query)
            .await
            .unwrap();
        assert_eq!(response, expected_response);
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_a_mismatched_transaction_id() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];

        let upstream = tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut request).await.unwrap();
            let response = [0x12, 0x35, 0x81, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });

        assert_eq!(
            forward_query(server_addr, loopback_interface(), &query)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn serves_udp_and_tcp_clients_from_tcp_upstream() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let mut length = [0; 2];
                stream.read_exact(&mut length).await.unwrap();
                let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut response).await.unwrap();
                response[2] |= 0x80;
                stream
                    .write_all(&(response.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(listen).await.unwrap();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let worker = tokio::task::spawn_local(serve(
                    upstream_addr,
                    Arc::from(loopback_interface()),
                    Arc::new(udp),
                    tcp,
                ));
                let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];

                let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                udp_client.send_to(&query, listen).await.unwrap();
                let mut udp_response = [0; 64];
                let (size, _) = timeout(QUERY_TIMEOUT, udp_client.recv_from(&mut udp_response))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    &udp_response[..size],
                    &[0x12, 0x34, 0x81, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,]
                );

                let mut tcp_client = TcpStream::connect(listen).await.unwrap();
                tcp_client
                    .write_all(&(query.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                tcp_client.write_all(&query).await.unwrap();
                let mut response_length = [0; 2];
                tcp_client.read_exact(&mut response_length).await.unwrap();
                let mut tcp_response = vec![0; usize::from(u16::from_be_bytes(response_length))];
                tcp_client.read_exact(&mut tcp_response).await.unwrap();
                assert_eq!(tcp_response, udp_response[..size]);
                worker.abort();
            })
            .await;
        upstream_worker.await.unwrap();
    }

    #[cfg(target_os = "macos")]
    fn loopback_interface() -> &'static str {
        "lo0"
    }

    #[cfg(target_os = "linux")]
    fn loopback_interface() -> &'static str {
        "lo"
    }
}
