use crate::batch_io::BatchIo;
use crate::packet::Packet;
use crate::sys::{PacketDevice, TunPi};
use crate::zprtun::ZprTunError;
use std::io;
use std::net::IpAddr;

#[derive(Clone, Copy)]
pub struct ReadinessSource;

#[derive(Clone, Copy)]
pub struct ReadinessInterest {
    pub readable: bool,
    pub writable: bool,
}

impl ReadinessInterest {
    pub const fn new(readable: bool, writable: bool) -> Self {
        Self { readable, writable }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadinessEvents {
    pub readable: bool,
    pub writable: bool,
}

pub struct ReadinessRequest<'a> {
    pub source: &'a ReadinessSource,
    pub interest: ReadinessInterest,
}

pub fn wait_for_readiness<const N: usize>(
    _requests: [ReadinessRequest<'_>; N],
    _timeout_millis: Option<u16>,
) -> io::Result<[ReadinessEvents; N]> {
    Err(unsupported_packet_io())
}

pub struct ZprTun;

impl ZprTun {
    pub fn name(&self) -> &str {
        "windows-unsupported"
    }

    pub fn new_mq(
        _ifname: Option<String>,
        _concurrency: usize,
        _address: Option<IpAddr>,
    ) -> Result<Vec<Self>, ZprTunError> {
        Err(ZprTunError::PlatformError(
            "Windows tunnel startup is unsupported in this compile-only build".into(),
        ))
    }

    pub fn set_carrier(&self, _carrier: bool) -> io::Result<()> {
        Err(unsupported_packet_io())
    }

    pub fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> io::Result<()> {
        Err(unsupported_packet_io())
    }

    pub fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> io::Result<()> {
        Err(unsupported_packet_io())
    }
}

impl PacketDevice for ZprTun {
    fn readiness_source(&self) -> io::Result<ReadinessSource> {
        Err(unsupported_packet_io())
    }

    fn packet_info_size(&self) -> usize {
        0
    }

    fn read_packets(
        &self,
        _batch_io: &mut BatchIo,
        _packets: &mut [Packet],
        _results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize> {
        Err(unsupported_packet_io())
    }

    fn write_packets(
        &self,
        _batch_io: &mut BatchIo,
        _packets: &[Packet],
        _results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize> {
        Err(unsupported_packet_io())
    }
}

fn unsupported_packet_io() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows packet I/O is unavailable in this compile-only build",
    )
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
