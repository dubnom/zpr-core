use crate::sys::TunPi;
use crate::sys::packet_fd::PacketFd;
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
