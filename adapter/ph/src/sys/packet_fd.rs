use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

pub(crate) struct PacketFd {
    fd: OwnedFd,
}

impl PacketFd {
    pub(crate) fn new(fd: OwnedFd) -> io::Result<Self> {
        let raw_fd = fd.as_fd().as_raw_fd();
        let mut socket_type = 0;
        let mut socket_type_len = std::mem::size_of_val(&socket_type) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut socket_type as *mut _ as *mut libc::c_void,
                &mut socket_type_len,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        if socket_type != libc::SOCK_DGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet-flow descriptor must be a datagram socket",
            ));
        }

        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }

        if flags & libc::O_NONBLOCK == 0
            && unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }
}

impl AsFd for PacketFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn packet_fd_is_nonblocking_and_preserves_datagrams() {
        let (device, host) = UnixDatagram::pair().unwrap();
        let device = PacketFd::new(device.into()).unwrap();
        let mut io = File::from(device.as_fd().try_clone_to_owned().unwrap());

        let flags = unsafe { libc::fcntl(device.as_fd().as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0);

        host.send(b"inbound packet").unwrap();
        let mut incoming = [0; 32];
        let length = io.read(&mut incoming).unwrap();
        assert_eq!(&incoming[..length], b"inbound packet");

        io.write_all(b"outbound packet").unwrap();
        let mut outgoing = [0; 32];
        let length = host.recv(&mut outgoing).unwrap();
        assert_eq!(&outgoing[..length], b"outbound packet");
    }

    #[test]
    fn packet_fd_rejects_stream_sockets() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let error = PacketFd::new(stream.into()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
