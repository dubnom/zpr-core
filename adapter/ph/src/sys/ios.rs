use crate::batch_io::BatchIo;
use crate::packet::Packet;
use crate::sys::TunPi;
use crate::sys::packet_fd::PacketFd;
use crate::sys::{PacketDevice, ReadinessSource};
use crate::zprtun::ZprTunError;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub struct ZprTun {
    packet_fd: PacketFd,
}

impl ZprTun {
    pub fn from_packet_fd(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            packet_fd: PacketFd::new(fd)?,
        })
    }

    pub fn name(&self) -> &str {
        "packet-flow"
    }

    pub fn new_mq(
        _ifname: Option<String>,
        _concurrency: usize,
        _address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        Err(ZprTunError::PlatformError(String::from(
            "iOS packet I/O must be supplied by a Network Extension host",
        )))
    }

    pub fn set_carrier(&self, _carrier: bool) -> io::Result<()> {
        Ok(())
    }

    pub fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> io::Result<()> {
        Err(host_managed_configuration_error())
    }

    pub fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> io::Result<()> {
        Err(host_managed_configuration_error())
    }
}

fn host_managed_configuration_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "iOS tunnel addresses are managed by the Network Extension host",
    )
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.packet_fd.as_fd()
    }
}

impl PacketDevice for ZprTun {
    fn readiness_source(&self) -> io::Result<ReadinessSource> {
        ReadinessSource::from_fd(self)
    }

    fn packet_info_size(&self) -> usize {
        0
    }

    fn read_packets(
        &self,
        batch_io: &mut BatchIo,
        packets: &mut [Packet],
        results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize> {
        batch_io.try_read_buf_batch(self, packets.iter_mut(), results)
    }

    fn write_packets(
        &self,
        batch_io: &mut BatchIo,
        packets: &[Packet],
        results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize> {
        batch_io.try_write_batch(self, packets.iter().map(Packet::body), results)
    }
}

pub struct TunPiImpl;

impl From<TunPiImpl> for TunPi {
    fn from(_: TunPiImpl) -> Self {
        Self {
            strip: false,
            proto: 0,
        }
    }
}

impl From<TunPi> for TunPiImpl {
    fn from(_: TunPi) -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn tunnel_creation_requires_a_host_supplied_packet_flow() {
        let Err(error) = ZprTun::new_mq(None, 1, None) else {
            panic!("iOS TUN creation must be delegated to the Network Extension host");
        };

        assert!(matches!(
            error,
            ZprTunError::PlatformError(message)
                if message == "iOS packet I/O must be supplied by a Network Extension host"
        ));
    }

    #[test]
    fn address_lifecycle_is_delegated_to_the_network_extension_host() {
        let (packet_socket, _peer) = UnixDatagram::pair().unwrap();
        let tun = ZprTun::from_packet_fd(OwnedFd::from(packet_socket)).unwrap();

        assert_eq!(tun.name(), "packet-flow");
        tun.set_carrier(true).unwrap();
        assert_eq!(
            tun.add_address(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            tun.clear_address(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn packet_flow_uses_raw_ip_packets_without_a_platform_header() {
        assert_eq!(std::mem::size_of::<TunPiImpl>(), 0);
    }
}
