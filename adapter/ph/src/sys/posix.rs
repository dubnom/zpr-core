pub mod notify;

#[path = "posix/readiness.rs"]
pub mod readiness;

pub use readiness::{ReadinessEvents, ReadinessInterest, ReadinessRequest, ReadinessSource};
use std::io;
use std::net::UdpSocket;

pub(crate) fn readiness_source_for_socket(socket: &UdpSocket) -> io::Result<ReadinessSource> {
    ReadinessSource::from_fd(socket)
}

pub fn wait_for_readiness<const N: usize>(
    requests: [ReadinessRequest<'_>; N],
    timeout_millis: Option<u16>,
) -> io::Result<[ReadinessEvents; N]> {
    readiness::wait(requests, timeout_millis)
}
