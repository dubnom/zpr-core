use crate::batch_io::BatchIo;
use crate::packet::Packet;
use crate::sys::windows_wintun::{self, Session};
use crate::sys::{PacketDevice, TunPi};
use crate::zprtun::ZprTunError;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct ReadinessSource(Arc<Session>);

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
    requests: [ReadinessRequest<'_>; N],
    timeout_millis: Option<u16>,
) -> io::Result<[ReadinessEvents; N]> {
    let readable_requests: Vec<usize> = requests
        .iter()
        .enumerate()
        .filter_map(|(index, request)| request.interest.readable.then_some(index))
        .collect();

    if readable_requests.is_empty() {
        if requests.iter().any(|request| request.interest.writable) {
            return Ok(std::array::from_fn(|index| ReadinessEvents {
                readable: false,
                writable: requests[index].interest.writable,
            }));
        }
        if let Some(timeout) = timeout_millis {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(timeout)));
            return Ok([ReadinessEvents::default(); N]);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot wait indefinitely without a readable Wintun event",
        ));
    }

    let handles: Vec<*mut std::ffi::c_void> = readable_requests
        .iter()
        .map(|index| requests[*index].source.0.read_wait_event() as *mut std::ffi::c_void)
        .collect();
    let signaled = windows_wintun::wait_for_events(&handles, timeout_millis)?;
    let mut events = [ReadinessEvents::default(); N];
    for (index, request) in requests.iter().enumerate() {
        events[index].writable = request.interest.writable;
    }

    if let Some(signaled) = signaled {
        for (event_index, request_index) in readable_requests.iter().enumerate() {
            let readable = if event_index == signaled {
                true
            } else {
                windows_wintun::poll_event(handles[event_index])?
            };
            events[*request_index].readable = readable;
        }
    }
    Ok(events)
}

pub struct ZprTun {
    name: String,
    session: Arc<Session>,
}

impl ZprTun {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
    ) -> Result<Vec<Self>, ZprTunError> {
        if concurrency != 1 {
            return Err(ZprTunError::PlatformError(
                "Wintun uses one session and requires concurrency (queues) to be 1".into(),
            ));
        }
        if address.is_some() {
            return Err(ZprTunError::PlatformError(
                "Windows address configuration is operator-managed and unsupported here".into(),
            ));
        }
        let name = ifname.ok_or_else(|| {
            ZprTunError::PlatformError(
                "an existing Wintun adapter name is required; adapter creation is disabled".into(),
            )
        })?;
        let config = windows_wintun::WintunConfig::from_environment()?;
        let api = windows_wintun::load_pinned_api(&config)?;
        let session = Arc::new(Session::open(api, &name)?);
        Ok(vec![Self { name, session }])
    }

    pub fn set_carrier(&self, _carrier: bool) -> io::Result<()> {
        Err(unsupported_operation(
            "Wintun carrier control is not available in this backend",
        ))
    }

    pub fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> io::Result<()> {
        Err(unsupported_operation(
            "Windows address configuration is operator-managed",
        ))
    }

    pub fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> io::Result<()> {
        Err(unsupported_operation(
            "Windows address configuration is operator-managed",
        ))
    }
}

impl PacketDevice for ZprTun {
    fn readiness_source(&self) -> io::Result<ReadinessSource> {
        Ok(ReadinessSource(Arc::clone(&self.session)))
    }

    fn packet_info_size(&self) -> usize {
        0
    }

    fn read_packets(
        &self,
        _batch_io: &mut BatchIo,
        packets: &mut [Packet],
        results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize> {
        Ok(self.session.read_packets(packets, results))
    }

    fn write_packets(
        &self,
        _batch_io: &mut BatchIo,
        packets: &[Packet],
        results: &mut Vec<io::Result<usize>>,
    ) -> io::Result<usize> {
        Ok(self.session.write_packets(packets, results))
    }
}

fn unsupported_operation(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
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
