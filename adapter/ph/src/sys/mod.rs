#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::TunPiImpl;
#[cfg(target_os = "linux")]
pub use self::linux::ZprTun;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::TunPiImpl;
#[cfg(target_os = "macos")]
pub use self::macos::ZprTun;

#[cfg(any(target_os = "ios", test))]
pub(crate) mod ios;
#[cfg(target_os = "ios")]
pub use self::ios::TunPiImpl;
#[cfg(target_os = "ios")]
pub use self::ios::ZprTun;

#[cfg(windows)]
pub use self::windows::{TunPiImpl, ZprTun};

#[cfg(any(target_os = "ios", test))]
pub(crate) mod packet_fd;
#[cfg(unix)]
pub(crate) mod posix;
#[cfg(windows)]
pub(crate) mod windows;
#[cfg(any(windows, test))]
mod windows_wintun;

#[cfg(unix)]
pub use self::posix::notify;
#[cfg(unix)]
pub use self::posix::{ReadinessInterest, ReadinessRequest, ReadinessSource, wait_for_readiness};
#[cfg(windows)]
pub use self::windows::{
    ReadinessEvents, ReadinessInterest, ReadinessRequest, ReadinessSource, wait_for_readiness,
};

use crate::batch_io::BatchIo;
use crate::packet::Packet;
use bytes::buf;
use std::io;

pub trait PacketDevice: Send + Sync {
    fn readiness_source(&self) -> io::Result<ReadinessSource>;

    fn packet_info_size(&self) -> usize;

    fn read_packets(
        &self,
        batch_io: &mut BatchIo,
        packets: &mut [Packet],
        results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize>;

    fn write_packets(
        &self,
        batch_io: &mut BatchIo,
        packets: &[Packet],
        results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize>;
}

#[cfg(unix)]
pub fn readiness_source_for_socket(
    socket: &std::net::UdpSocket,
) -> std::io::Result<ReadinessSource> {
    posix::readiness_source_for_socket(socket)
}

#[cfg(windows)]
pub fn readiness_source_for_socket(
    _socket: &std::net::UdpSocket,
) -> std::io::Result<ReadinessSource> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows packet I/O is unavailable in this compile-only build",
    ))
}

/// per-packet packet info
#[derive(Clone, Copy)]
pub struct TunPi {
    // the inbound packet was truncated (ignored outbound)
    pub strip: bool,
    /// Ethertype of packet
    pub proto: u16,
}

impl TunPi {
    /// The size of a per-packet packet info structure.
    pub const PI_SIZE: usize = std::mem::size_of::<TunPiImpl>();

    /// Read per-packet packet info from a `Buf`.
    pub fn read_pi<B: buf::Buf>(buf: &mut B) -> TunPi {
        let mut os_pi = std::mem::MaybeUninit::<TunPiImpl>::uninit();
        let slice = os_pi.as_mut_ptr();
        buf.copy_to_slice(unsafe {
            /* SAFETY: we immediately initialize */
            std::slice::from_raw_parts_mut(slice as *mut u8, TunPi::PI_SIZE)
        });
        unsafe {
            /* SAFETY: was just initialized */
            os_pi.assume_init()
        }
        .into()
    }

    /// Write per-packet packet info into a `BufMut`.
    pub fn write_pi<B: buf::BufMut>(buf: &mut B, pi: TunPi) {
        let os_pi: TunPiImpl = pi.into();
        buf.put(unsafe {
            /* SAFETY: we are reading exactly the structure */
            std::slice::from_raw_parts((&os_pi as *const _) as *const u8, TunPi::PI_SIZE)
        });
    }
}
