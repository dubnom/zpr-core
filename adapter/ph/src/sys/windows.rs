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

const STACK_READINESS_CAPACITY: usize = 64; // Win32's maximum wait-object count.

fn collect_readable_indices(
    readable_interests: impl Iterator<Item = bool>,
    readable_indices: &mut [usize],
) -> Option<usize> {
    let mut readable_count = 0;
    for (index, readable) in readable_interests.enumerate() {
        if readable {
            let Some(slot) = readable_indices.get_mut(readable_count) else {
                return None;
            };
            *slot = index;
            readable_count += 1;
        }
    }
    Some(readable_count)
}

fn collect_readable_indices_fallback(readable_interests: impl Iterator<Item = bool>) -> Vec<usize> {
    readable_interests
        .enumerate()
        .filter_map(|(index, readable)| readable.then_some(index))
        .collect()
}

fn fill_readiness_handles(
    requests: &[ReadinessRequest<'_>],
    readable_requests: &[usize],
    handles: &mut [*mut std::ffi::c_void],
) {
    for (handle, request_index) in handles.iter_mut().zip(readable_requests.iter().copied()) {
        *handle = requests[request_index].source.0.read_wait_event() as *mut std::ffi::c_void;
    }
}

fn map_readiness_events<const N: usize>(
    writable_interests: impl Iterator<Item = bool>,
    readable_requests: &[usize],
    handles: &[*mut std::ffi::c_void],
    signaled: Option<usize>,
    mut poll_event: impl FnMut(*mut std::ffi::c_void) -> io::Result<bool>,
) -> io::Result<[ReadinessEvents; N]> {
    let mut events = [ReadinessEvents::default(); N];
    for (event, writable) in events.iter_mut().zip(writable_interests) {
        event.writable = writable;
    }

    if let Some(signaled) = signaled {
        for (event_index, request_index) in readable_requests.iter().copied().enumerate() {
            let readable = if event_index == signaled {
                true
            } else {
                poll_event(handles[event_index])?
            };
            events[request_index].readable = readable;
        }
    }

    Ok(events)
}

fn wait_for_readiness_with_buffers<const N: usize>(
    requests: [ReadinessRequest<'_>; N],
    timeout_millis: Option<u16>,
    readable_requests: &[usize],
    handles: &[*mut std::ffi::c_void],
) -> io::Result<[ReadinessEvents; N]> {
    let signaled = windows_wintun::wait_for_events(handles, timeout_millis)?;
    map_readiness_events(
        requests.iter().map(|request| request.interest.writable),
        readable_requests,
        handles,
        signaled,
        windows_wintun::poll_event,
    )
}

pub fn wait_for_readiness<const N: usize>(
    requests: [ReadinessRequest<'_>; N],
    timeout_millis: Option<u16>,
) -> io::Result<[ReadinessEvents; N]> {
    let mut readable_requests = [0; STACK_READINESS_CAPACITY];
    let readable_count = collect_readable_indices(
        requests.iter().map(|request| request.interest.readable),
        &mut readable_requests,
    );

    let Some(readable_count) = readable_count else {
        let readable_requests = collect_readable_indices_fallback(
            requests.iter().map(|request| request.interest.readable),
        );
        let mut handles = vec![std::ptr::null_mut(); readable_requests.len()];
        fill_readiness_handles(&requests, &readable_requests, &mut handles);
        return wait_for_readiness_with_buffers(
            requests,
            timeout_millis,
            &readable_requests,
            &handles,
        );
    };

    if readable_count == 0 {
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

    let mut handles = [std::ptr::null_mut(); STACK_READINESS_CAPACITY];
    fill_readiness_handles(
        &requests,
        &readable_requests[..readable_count],
        &mut handles[..readable_count],
    );
    wait_for_readiness_with_buffers(
        requests,
        timeout_millis,
        &readable_requests[..readable_count],
        &handles[..readable_count],
    )
}

#[cfg(test)]
mod tests {
    use super::{
        STACK_READINESS_CAPACITY, collect_readable_indices, collect_readable_indices_fallback,
        map_readiness_events,
    };
    use std::cell::Cell;
    use std::io;
    use std::time::Instant;

    #[test]
    fn collect_readable_indices_handles_no_readable_requests() {
        let mut indices = [usize::MAX; 3];
        let count = collect_readable_indices([false, false, false].into_iter(), &mut indices);

        assert_eq!(count, Some(0));
        assert_eq!(indices, [usize::MAX; 3]);
    }

    #[test]
    fn collect_readable_indices_preserves_request_order() {
        let mut indices = [usize::MAX; 5];
        let count =
            collect_readable_indices([true, false, true, false, true].into_iter(), &mut indices);

        let count = count.unwrap();
        assert_eq!(count, 3);
        assert_eq!(&indices[..count], &[0, 2, 4]);
    }

    #[test]
    fn collect_readable_indices_handles_all_readable_requests() {
        let mut indices = [usize::MAX; 3];
        let count = collect_readable_indices([true, true, true].into_iter(), &mut indices);

        assert_eq!(count, Some(3));
        assert_eq!(indices, [0, 1, 2]);
    }

    #[test]
    fn collect_readable_indices_uses_stack_capacity_and_keeps_large_request_indices() {
        let mut indices = [usize::MAX; STACK_READINESS_CAPACITY];
        let count = collect_readable_indices(
            (0..STACK_READINESS_CAPACITY + 1).map(|index| index == STACK_READINESS_CAPACITY),
            &mut indices,
        );

        assert_eq!(count, Some(1));
        assert_eq!(indices[0], STACK_READINESS_CAPACITY);
    }

    #[test]
    fn collect_readable_indices_signals_fallback_when_stack_capacity_is_exceeded() {
        let mut indices = [usize::MAX; STACK_READINESS_CAPACITY];
        let count = collect_readable_indices(
            std::iter::repeat_n(true, STACK_READINESS_CAPACITY + 1),
            &mut indices,
        );

        assert_eq!(count, None);
        assert_eq!(indices, std::array::from_fn(|index| index));
    }

    #[test]
    fn fallback_keeps_all_indices_beyond_stack_capacity() {
        let indices = collect_readable_indices_fallback(std::iter::repeat_n(
            true,
            STACK_READINESS_CAPACITY + 1,
        ));

        assert_eq!(indices.len(), STACK_READINESS_CAPACITY + 1);
        assert_eq!(indices[STACK_READINESS_CAPACITY], STACK_READINESS_CAPACITY);
    }

    #[test]
    fn readiness_mapping_preserves_duplicate_handles_and_request_order() {
        let handle = std::ptr::dangling_mut::<std::ffi::c_void>();
        let handles = [handle, handle];
        let readable_requests = [1, 3];
        let writable = [true, false, true, false].into_iter();
        let mut polled = 0;
        let events =
            map_readiness_events::<4>(writable, &readable_requests, &handles, Some(0), |_| {
                polled += 1;
                Ok(false)
            })
            .unwrap();

        assert_eq!(
            events,
            [
                super::ReadinessEvents {
                    readable: false,
                    writable: true
                },
                super::ReadinessEvents {
                    readable: true,
                    writable: false
                },
                super::ReadinessEvents {
                    readable: false,
                    writable: true
                },
                super::ReadinessEvents {
                    readable: false,
                    writable: false
                },
            ]
        );
        assert_eq!(polled, 1);
    }

    #[test]
    fn timeout_keeps_requests_unreadable_and_preserves_writable_state() {
        let handle = std::ptr::dangling_mut::<std::ffi::c_void>();
        let handles = [handle];
        let readable_requests = [0];
        let polled = Cell::new(false);
        let events = map_readiness_events::<2>(
            [true, false].into_iter(),
            &readable_requests,
            &handles,
            None,
            |_| {
                polled.set(true);
                Ok(false)
            },
        )
        .unwrap();

        assert!(!polled.get());
        assert_eq!(
            events,
            [
                super::ReadinessEvents {
                    readable: false,
                    writable: true
                },
                super::ReadinessEvents {
                    readable: false,
                    writable: false
                },
            ]
        );
    }

    #[test]
    fn readiness_mapping_propagates_poll_errors() {
        let handle = std::ptr::dangling_mut::<std::ffi::c_void>();
        let error = map_readiness_events::<2>(
            [false, false].into_iter(),
            &[0, 1],
            &[handle, handle],
            Some(0),
            |_| Err(io::Error::new(io::ErrorKind::Interrupted, "poll failure")),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    #[ignore = "synthetic bookkeeping benchmark; run explicitly with --release"]
    fn benchmark_readiness_bookkeeping() {
        const ITERATIONS: usize = 1_000_000;
        let interests = [true, false, true, false, true];

        let baseline_start = Instant::now();
        for _ in 0..ITERATIONS {
            let indices: Vec<_> = interests
                .iter()
                .enumerate()
                .filter_map(|(index, readable)| readable.then_some(index))
                .collect();
            let handles: Vec<_> = indices.iter().map(|index| index + 1).collect();
            std::hint::black_box((indices, handles));
        }
        let baseline_elapsed = baseline_start.elapsed();

        let stack_start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut indices = [0; STACK_READINESS_CAPACITY];
            let count = collect_readable_indices(interests.iter().copied(), &mut indices).unwrap();
            let mut handles = [0; STACK_READINESS_CAPACITY];
            for (handle, index) in handles[..count].iter_mut().zip(indices[..count].iter()) {
                *handle = index + 1;
            }
            std::hint::black_box((&indices[..count], &handles[..count]));
        }
        let stack_elapsed = stack_start.elapsed();

        eprintln!("iterations={ITERATIONS} baseline={baseline_elapsed:?} stack={stack_elapsed:?}");
    }
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
        let name = validate_new_mq_options(ifname, concurrency, address)?;
        let create_adapter = windows_wintun::create_adapter_requested_from_environment()?;
        let config = windows_wintun::WintunConfig::from_environment()?;
        let api = windows_wintun::load_pinned_api(&config)?;
        Self::new_with_api(name, api, create_adapter)
    }

    fn new_mq_with_api(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
        api: Arc<dyn windows_wintun::WintunApi>,
        create_adapter: bool,
    ) -> Result<Vec<Self>, ZprTunError> {
        let name = validate_new_mq_options(ifname, concurrency, address)?;
        Self::new_with_api(name, api, create_adapter)
    }

    fn new_with_api(
        name: String,
        api: Arc<dyn windows_wintun::WintunApi>,
        create_adapter: bool,
    ) -> Result<Vec<Self>, ZprTunError> {
        let session = if create_adapter {
            Session::create(api, &name)?
        } else {
            Session::open(api, &name)?
        };
        Ok(vec![Self {
            name,
            session: Arc::new(session),
        }])
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

fn validate_new_mq_options(
    ifname: Option<String>,
    concurrency: usize,
    address: Option<IpAddr>,
) -> Result<String, ZprTunError> {
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
        ZprTunError::PlatformError("an explicit Wintun adapter name is required".into())
    })?;
    Ok(name)
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

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeState {
        opened_name: Option<String>,
        created_name: Option<String>,
        created_tunnel_type: Option<String>,
        open_calls: usize,
        create_calls: usize,
        session_ends: usize,
        closed_adapters: Vec<usize>,
    }

    #[derive(Default)]
    struct FakeApi(Mutex<FakeState>);

    impl windows_wintun::WintunApi for FakeApi {
        fn open_adapter(&self, name: &str) -> io::Result<usize> {
            let mut state = self.0.lock().unwrap();
            state.open_calls += 1;
            state.opened_name = Some(name.to_owned());
            Ok(11)
        }

        fn create_adapter(&self, name: &str, tunnel_type: &str) -> io::Result<usize> {
            let mut state = self.0.lock().unwrap();
            state.create_calls += 1;
            state.created_name = Some(name.to_owned());
            state.created_tunnel_type = Some(tunnel_type.to_owned());
            Ok(22)
        }

        fn close_adapter(&self, adapter: usize) {
            self.0.lock().unwrap().closed_adapters.push(adapter);
        }

        fn start_session(&self, _adapter: usize, _capacity: u32) -> io::Result<usize> {
            Ok(33)
        }

        fn end_session(&self, _session: usize) {
            self.0.lock().unwrap().session_ends += 1;
        }

        fn read_wait_event(&self, _session: usize) -> io::Result<usize> {
            Ok(44)
        }

        fn receive_packet(&self, _session: usize) -> io::Result<Option<windows_wintun::RawPacket>> {
            Ok(None)
        }

        fn release_receive_packet(&self, _session: usize, _packet: std::ptr::NonNull<u8>) {}

        fn allocate_send_packet(
            &self,
            _session: usize,
            _size: usize,
        ) -> io::Result<std::ptr::NonNull<u8>> {
            Err(io::Error::other("not used by constructor tests"))
        }

        fn send_packet(&self, _session: usize, _packet: std::ptr::NonNull<u8>) {}
    }

    #[test]
    fn constructor_opens_existing_adapter_by_default() {
        let api = Arc::new(FakeApi::default());
        let devices =
            ZprTun::new_mq_with_api(Some("existing".into()), 1, None, api.clone(), false).unwrap();
        assert_eq!(devices[0].name(), "existing");
        {
            let state = api.0.lock().unwrap();
            assert_eq!(state.open_calls, 1);
            assert_eq!(state.opened_name.as_deref(), Some("existing"));
            assert_eq!(state.create_calls, 0);
        }

        drop(devices);
        let state = api.0.lock().unwrap();
        assert_eq!(state.session_ends, 1);
        assert_eq!(state.closed_adapters.as_slice(), &[11]);
    }

    #[test]
    fn constructor_creates_only_when_explicitly_requested() {
        let api = Arc::new(FakeApi::default());
        let devices =
            ZprTun::new_mq_with_api(Some("new-zpr".into()), 1, None, api.clone(), true).unwrap();
        {
            let state = api.0.lock().unwrap();
            assert_eq!(state.open_calls, 0);
            assert_eq!(state.create_calls, 1);
            assert_eq!(state.created_name.as_deref(), Some("new-zpr"));
            assert_eq!(state.created_tunnel_type.as_deref(), Some("ZPR"));
        }

        drop(devices);
        let state = api.0.lock().unwrap();
        assert_eq!(state.session_ends, 1);
        assert_eq!(state.closed_adapters.as_slice(), &[22]);
    }

    #[test]
    fn constructor_requires_an_explicit_name_before_api_calls() {
        let api = Arc::new(FakeApi::default());
        assert!(ZprTun::new_mq_with_api(None, 1, None, api.clone(), true).is_err());
        let state = api.0.lock().unwrap();
        assert_eq!(state.open_calls, 0);
        assert_eq!(state.create_calls, 0);
    }
}
