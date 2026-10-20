use crate::packet::Packet;
use bytes::BufMut;
use std::io;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::Arc;

const MAX_PACKET_SIZE: usize = 0xffff;
const SESSION_CAPACITY: u32 = 0x20000;

#[derive(Clone, Debug)]
pub(crate) struct WintunConfig {
    dll_path: PathBuf,
    sha256: [u8; 32],
}

impl WintunConfig {
    pub(crate) fn new(dll_path: PathBuf, sha256: &str) -> io::Result<Self> {
        if !dll_path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Wintun DLL path must be absolute",
            ));
        }

        let sha256 = parse_sha256(sha256)?;
        Ok(Self { dll_path, sha256 })
    }

    #[cfg(windows)]
    pub(crate) fn from_environment() -> io::Result<Self> {
        let dll_path = std::env::var_os("ZPR_WINTUN_DLL_PATH").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ZPR_WINTUN_DLL_PATH must specify an absolute Wintun DLL path",
            )
        })?;
        let sha256 = std::env::var("ZPR_WINTUN_DLL_SHA256").map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ZPR_WINTUN_DLL_SHA256 must specify the pinned Wintun DLL SHA-256",
            )
        })?;
        Self::new(dll_path.into(), &sha256)
    }
}

fn parse_sha256(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Wintun DLL SHA-256 must contain exactly 64 hexadecimal characters",
        ));
    }

    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Wintun DLL SHA-256 contains invalid hexadecimal characters",
            )
        })?;
    }
    Ok(digest)
}

fn sha256(contents: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, contents);
    let mut result = [0; 32];
    result.copy_from_slice(digest.as_ref());
    result
}

fn verify_sha256(expected: &[u8; 32], contents: &[u8]) -> bool {
    let actual = sha256(contents);
    actual
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[derive(Clone, Copy)]
pub(crate) struct RawPacket {
    ptr: NonNull<u8>,
    size: usize,
}

pub(crate) trait WintunApi: Send + Sync {
    fn open_adapter(&self, name: &str) -> io::Result<usize>;
    fn close_adapter(&self, adapter: usize);
    fn start_session(&self, adapter: usize, capacity: u32) -> io::Result<usize>;
    fn end_session(&self, session: usize);
    fn read_wait_event(&self, session: usize) -> io::Result<usize>;
    fn receive_packet(&self, session: usize) -> io::Result<Option<RawPacket>>;
    fn release_receive_packet(&self, session: usize, packet: NonNull<u8>);
    fn allocate_send_packet(&self, session: usize, size: usize) -> io::Result<NonNull<u8>>;
    fn send_packet(&self, session: usize, packet: NonNull<u8>);
}

struct AdapterHandle {
    api: Arc<dyn WintunApi>,
    handle: usize,
}

impl AdapterHandle {
    fn open(api: Arc<dyn WintunApi>, name: &str) -> io::Result<Self> {
        let handle = api.open_adapter(name)?;
        Ok(Self { api, handle })
    }
}

impl Drop for AdapterHandle {
    fn drop(&mut self) {
        self.api.close_adapter(self.handle);
    }
}

struct SessionHandle {
    adapter: AdapterHandle,
    handle: usize,
}

impl SessionHandle {
    fn start(adapter: AdapterHandle) -> io::Result<Self> {
        let handle = adapter
            .api
            .start_session(adapter.handle, SESSION_CAPACITY)?;
        Ok(Self { adapter, handle })
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.adapter.api.end_session(self.handle);
    }
}

pub(crate) struct Session {
    session: SessionHandle,
    read_wait_event: usize,
}

// Wintun permits concurrent packet operations; the Arc keeps both handles alive through calls.
unsafe impl Send for Session {}
unsafe impl Sync for Session {}

impl Session {
    pub(crate) fn open(api: Arc<dyn WintunApi>, adapter_name: &str) -> io::Result<Self> {
        if adapter_name.is_empty() || adapter_name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Wintun adapter name must be non-empty and contain no NUL character",
            ));
        }

        let adapter = AdapterHandle::open(api, adapter_name)?;
        let session = SessionHandle::start(adapter)?;
        let read_wait_event = session.adapter.api.read_wait_event(session.handle)?;
        if read_wait_event == 0 {
            return Err(io::Error::other("Wintun returned a null read-wait event"));
        }
        Ok(Self {
            session,
            read_wait_event,
        })
    }

    pub(crate) fn read_wait_event(&self) -> usize {
        self.read_wait_event
    }

    fn read_packets(&self, packets: &mut [Packet], results: &mut Vec<io::Result<usize>>) -> usize {
        let mut count = 0;
        for packet in packets {
            let raw_packet = match self.session.adapter.api.receive_packet(self.session.handle) {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(error) => {
                    results.push(Err(error));
                    count += 1;
                    break;
                }
            };
            let guard = ReceivePacketGuard {
                api: self.session.adapter.api.as_ref(),
                session: self.session.handle,
                packet: raw_packet.ptr,
            };

            let result = if raw_packet.size == 0 || raw_packet.size > MAX_PACKET_SIZE {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun returned an invalid packet size",
                ))
            } else if raw_packet.size > packet.remaining_mut() {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun packet exceeds available packet-buffer tailroom",
                ))
            } else {
                let contents = unsafe {
                    // SAFETY: Wintun owns this readable region until the guard releases it.
                    std::slice::from_raw_parts(raw_packet.ptr.as_ptr(), raw_packet.size)
                };
                packet.put_slice(contents);
                Ok(raw_packet.size)
            };

            drop(guard);
            results.push(result);
            count += 1;
        }
        count
    }

    fn write_packets(&self, packets: &[Packet], results: &mut Vec<io::Result<usize>>) -> usize {
        let mut count = 0;
        for packet in packets {
            let contents = packet.body();
            if contents.is_empty() || contents.len() > MAX_PACKET_SIZE {
                results.push(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Wintun packet size must be between 1 and 65535 bytes",
                )));
                count += 1;
                continue;
            }

            let send_packet = match self
                .session
                .adapter
                .api
                .allocate_send_packet(self.session.handle, contents.len())
            {
                Ok(packet) => packet,
                Err(error) => {
                    let would_block = error.kind() == io::ErrorKind::WouldBlock;
                    results.push(Err(error));
                    count += 1;
                    if would_block {
                        break;
                    }
                    continue;
                }
            };

            unsafe {
                // SAFETY: Wintun allocated a writable packet buffer of exactly this size.
                std::ptr::copy_nonoverlapping(
                    contents.as_ptr(),
                    send_packet.as_ptr(),
                    contents.len(),
                );
            }
            self.session
                .adapter
                .api
                .send_packet(self.session.handle, send_packet);
            results.push(Ok(contents.len()));
            count += 1;
        }
        count
    }
}

struct ReceivePacketGuard<'a> {
    api: &'a dyn WintunApi,
    session: usize,
    packet: NonNull<u8>,
}

impl Drop for ReceivePacketGuard<'_> {
    fn drop(&mut self) {
        self.api.release_receive_packet(self.session, self.packet);
    }
}

#[cfg(windows)]
pub(crate) fn load_pinned_api(config: &WintunConfig) -> io::Result<Arc<dyn WintunApi>> {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;

    let path = std::fs::canonicalize(&config.dll_path)?;
    if !path.is_absolute() || !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Wintun DLL must resolve to an absolute regular file",
        ));
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    if !verify_sha256(&config.sha256, &contents) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Wintun DLL SHA-256 does not match the configured pin",
        ));
    }

    let library = Library::load(&path)?;
    let api = unsafe {
        // SAFETY: required exports are resolved from the hash-pinned Wintun DLL.
        DynamicApi::load(library)?
    };
    Ok(Arc::new(api))
}

#[cfg(windows)]
struct Library(usize);

#[cfg(windows)]
impl Library {
    fn load(path: &std::path::Path) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;

        const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x00000100;
        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x00000800;

        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            // SAFETY: path is a null-terminated UTF-16 path; flags restrict dependency search.
            LoadLibraryExW(
                path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle as usize))
        }
    }
}

#[cfg(windows)]
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: this handle was returned by LoadLibraryExW and is released once.
            FreeLibrary(self.0 as *mut std::ffi::c_void);
        }
    }
}

#[cfg(windows)]
struct DynamicApi {
    _library: Library,
    open_adapter: unsafe extern "system" fn(*const u16) -> *mut std::ffi::c_void,
    close_adapter: unsafe extern "system" fn(*mut std::ffi::c_void),
    start_session: unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> *mut std::ffi::c_void,
    end_session: unsafe extern "system" fn(*mut std::ffi::c_void),
    get_read_wait_event: unsafe extern "system" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void,
    receive_packet: unsafe extern "system" fn(*mut std::ffi::c_void, *mut u32) -> *mut u8,
    release_receive_packet: unsafe extern "system" fn(*mut std::ffi::c_void, *const u8),
    allocate_send_packet: unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> *mut u8,
    send_packet: unsafe extern "system" fn(*mut std::ffi::c_void, *const u8),
}

#[cfg(windows)]
impl DynamicApi {
    unsafe fn load(library: Library) -> io::Result<Self> {
        unsafe fn symbol<T: Copy>(library: usize, name: &'static [u8]) -> io::Result<T> {
            let address = unsafe {
                // SAFETY: name is a static NUL-terminated export name.
                GetProcAddress(library as *mut std::ffi::c_void, name.as_ptr().cast())
            };
            if address.is_null() {
                return Err(io::Error::last_os_error());
            }
            if std::mem::size_of::<T>() != std::mem::size_of_val(&address) {
                return Err(io::Error::other("unexpected Wintun function pointer size"));
            }
            Ok(unsafe {
                // SAFETY: callers request the documented function-pointer type for each export.
                std::mem::transmute_copy(&address)
            })
        }

        let handle = library.0;
        Ok(Self {
            open_adapter: unsafe { symbol(handle, b"WintunOpenAdapter\0")? },
            close_adapter: unsafe { symbol(handle, b"WintunCloseAdapter\0")? },
            start_session: unsafe { symbol(handle, b"WintunStartSession\0")? },
            end_session: unsafe { symbol(handle, b"WintunEndSession\0")? },
            get_read_wait_event: unsafe { symbol(handle, b"WintunGetReadWaitEvent\0")? },
            receive_packet: unsafe { symbol(handle, b"WintunReceivePacket\0")? },
            release_receive_packet: unsafe { symbol(handle, b"WintunReleaseReceivePacket\0")? },
            allocate_send_packet: unsafe { symbol(handle, b"WintunAllocateSendPacket\0")? },
            send_packet: unsafe { symbol(handle, b"WintunSendPacket\0")? },
            _library: library,
        })
    }
}

#[cfg(windows)]
impl WintunApi for DynamicApi {
    fn open_adapter(&self, name: &str) -> io::Result<usize> {
        use std::os::windows::ffi::OsStrExt;

        let name: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            // SAFETY: name is a NUL-terminated UTF-16 adapter name.
            (self.open_adapter)(name.as_ptr())
        };
        non_null_handle(handle)
    }

    fn close_adapter(&self, adapter: usize) {
        unsafe {
            // SAFETY: adapter is owned by AdapterHandle.
            (self.close_adapter)(adapter as *mut std::ffi::c_void);
        }
    }

    fn start_session(&self, adapter: usize, capacity: u32) -> io::Result<usize> {
        let handle = unsafe {
            // SAFETY: adapter is live and the capacity meets Wintun's documented constraints.
            (self.start_session)(adapter as *mut std::ffi::c_void, capacity)
        };
        non_null_handle(handle)
    }

    fn end_session(&self, session: usize) {
        unsafe {
            // SAFETY: session is owned by SessionHandle.
            (self.end_session)(session as *mut std::ffi::c_void);
        }
    }

    fn read_wait_event(&self, session: usize) -> io::Result<usize> {
        let event = unsafe {
            // SAFETY: session is live and Wintun retains ownership of this event.
            (self.get_read_wait_event)(session as *mut std::ffi::c_void)
        };
        non_null_handle(event)
    }

    fn receive_packet(&self, session: usize) -> io::Result<Option<RawPacket>> {
        const ERROR_NO_MORE_ITEMS: i32 = 259;

        let mut size = 0_u32;
        let packet = unsafe {
            // SAFETY: size is a valid output pointer and session is live.
            (self.receive_packet)(session as *mut std::ffi::c_void, &mut size)
        };
        let Some(packet) = NonNull::new(packet) else {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS) {
                Ok(None)
            } else {
                Err(error)
            };
        };
        Ok(Some(RawPacket {
            ptr: packet,
            size: size as usize,
        }))
    }

    fn release_receive_packet(&self, session: usize, packet: NonNull<u8>) {
        unsafe {
            // SAFETY: packet was returned by WintunReceivePacket for this session.
            (self.release_receive_packet)(session as *mut std::ffi::c_void, packet.as_ptr());
        }
    }

    fn allocate_send_packet(&self, session: usize, size: usize) -> io::Result<NonNull<u8>> {
        const ERROR_BUFFER_OVERFLOW: i32 = 111;

        let packet = unsafe {
            // SAFETY: size is bounded to Wintun's maximum and session is live.
            (self.allocate_send_packet)(session as *mut std::ffi::c_void, size as u32)
        };
        NonNull::new(packet).ok_or_else(|| {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW) {
                io::Error::new(io::ErrorKind::WouldBlock, error)
            } else {
                error
            }
        })
    }

    fn send_packet(&self, session: usize, packet: NonNull<u8>) {
        unsafe {
            // SAFETY: WintunSendPacket consumes and releases this allocated send packet.
            (self.send_packet)(session as *mut std::ffi::c_void, packet.as_ptr());
        }
    }
}

#[cfg(windows)]
fn non_null_handle(handle: *mut std::ffi::c_void) -> io::Result<usize> {
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(handle as usize)
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(
        file_name: *const u16,
        file: *mut std::ffi::c_void,
        flags: u32,
    ) -> *mut std::ffi::c_void;
    fn FreeLibrary(module: *mut std::ffi::c_void) -> i32;
    fn GetProcAddress(module: *mut std::ffi::c_void, name: *const i8) -> *mut std::ffi::c_void;
    fn WaitForMultipleObjects(
        count: u32,
        handles: *const *mut std::ffi::c_void,
        wait_all: i32,
        timeout: u32,
    ) -> u32;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, timeout: u32) -> u32;
}

#[cfg(windows)]
pub(crate) fn wait_for_events(
    handles: &[*mut std::ffi::c_void],
    timeout: Option<u16>,
) -> io::Result<Option<usize>> {
    const MAXIMUM_WAIT_OBJECTS: usize = 64;
    const INFINITE: u32 = u32::MAX;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_FAILED: u32 = u32::MAX;

    if handles.is_empty() {
        if let Some(timeout) = timeout {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(timeout)));
            return Ok(None);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot wait indefinitely without Wintun events",
        ));
    }
    if handles.len() > MAXIMUM_WAIT_OBJECTS || handles.iter().any(|handle| handle.is_null()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid number or value of Wintun read-wait events",
        ));
    }

    let timeout = timeout.map(u32::from).unwrap_or(INFINITE);
    let result = unsafe {
        // SAFETY: all event handles are live, and the slice length matches count.
        WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout)
    };
    if result == WAIT_TIMEOUT {
        return Ok(None);
    }
    if result == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    let index = result
        .checked_sub(WAIT_OBJECT_0)
        .ok_or_else(|| io::Error::other("WaitForMultipleObjects returned an unexpected result"))?
        as usize;
    if index >= handles.len() {
        return Err(io::Error::other(
            "WaitForMultipleObjects returned an out-of-range event",
        ));
    }
    Ok(Some(index))
}

#[cfg(windows)]
pub(crate) fn poll_event(handle: *mut std::ffi::c_void) -> io::Result<bool> {
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_FAILED: u32 = u32::MAX;

    let result = unsafe {
        // SAFETY: caller holds the session owning this event.
        WaitForSingleObject(handle, 0)
    };
    match result {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other(
            "WaitForSingleObject returned an unexpected result",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestTempDir {
        path: Option<PathBuf>,
    }

    impl TestTempDir {
        fn new() -> io::Result<Self> {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

            let temp_root = std::env::temp_dir();
            if !temp_root.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "system temporary directory is not absolute",
                ));
            }

            loop {
                let path = temp_root.join(format!(
                    "zpr-wintun-test-{}-{}",
                    std::process::id(),
                    NEXT_ID.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Ok(Self { path: Some(path) }),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
        }

        fn path(&self) -> &std::path::Path {
            self.path.as_deref().expect("temporary directory is active")
        }

        fn cleanup(mut self) -> io::Result<()> {
            let path = self.path.as_deref().expect("temporary directory is active");
            std::fs::remove_dir(path)?;
            self.path = None;
            Ok(())
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            if let Some(path) = self.path.take() {
                if let Err(error) = std::fs::remove_dir(&path) {
                    if error.kind() != io::ErrorKind::NotFound {
                        eprintln!(
                            "failed to clean up Wintun test directory {}: {error}",
                            path.display()
                        );
                    }
                }
            }
        }
    }

    #[derive(Default)]
    struct FakeState {
        fail_start: bool,
        fail_event: bool,
        fail_receive: bool,
        fail_send: bool,
        missing_adapter: bool,
        incoming: VecDeque<Box<[u8]>>,
        active_receive: Option<Box<[u8]>>,
        active_send: Option<Box<[u8]>>,
        sent: Vec<Vec<u8>>,
        receive_releases: usize,
        session_ends: usize,
        adapter_closes: usize,
    }

    #[derive(Default)]
    struct FakeApi(Mutex<FakeState>);

    impl WintunApi for FakeApi {
        fn open_adapter(&self, _name: &str) -> io::Result<usize> {
            if self.0.lock().unwrap().missing_adapter {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "fake adapter not found",
                ))
            } else {
                Ok(1)
            }
        }

        fn close_adapter(&self, _adapter: usize) {
            self.0.lock().unwrap().adapter_closes += 1;
        }

        fn start_session(&self, _adapter: usize, capacity: u32) -> io::Result<usize> {
            assert_eq!(capacity, SESSION_CAPACITY);
            if self.0.lock().unwrap().fail_start {
                Err(io::Error::other("fake session start failure"))
            } else {
                Ok(2)
            }
        }

        fn end_session(&self, _session: usize) {
            self.0.lock().unwrap().session_ends += 1;
        }

        fn read_wait_event(&self, _session: usize) -> io::Result<usize> {
            if self.0.lock().unwrap().fail_event {
                Err(io::Error::other("fake event retrieval failure"))
            } else {
                Ok(3)
            }
        }

        fn receive_packet(&self, _session: usize) -> io::Result<Option<RawPacket>> {
            let mut state = self.0.lock().unwrap();
            if state.fail_receive {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fake receive failure",
                ));
            }
            let Some(packet) = state.incoming.pop_front() else {
                return Ok(None);
            };
            let ptr = NonNull::new(packet.as_ptr() as *mut u8).unwrap();
            let size = packet.len();
            state.active_receive = Some(packet);
            Ok(Some(RawPacket { ptr, size }))
        }

        fn release_receive_packet(&self, _session: usize, packet: NonNull<u8>) {
            let mut state = self.0.lock().unwrap();
            assert_eq!(
                state.active_receive.as_ref().unwrap().as_ptr(),
                packet.as_ptr()
            );
            state.active_receive.take();
            state.receive_releases += 1;
        }

        fn allocate_send_packet(&self, _session: usize, size: usize) -> io::Result<NonNull<u8>> {
            let mut state = self.0.lock().unwrap();
            if state.fail_send {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fake send allocation failure",
                ));
            }
            let mut packet = vec![0; size].into_boxed_slice();
            let ptr = NonNull::new(packet.as_mut_ptr()).unwrap();
            state.active_send = Some(packet);
            Ok(ptr)
        }

        fn send_packet(&self, _session: usize, packet: NonNull<u8>) {
            let mut state = self.0.lock().unwrap();
            let packet_buf = state.active_send.take().unwrap();
            assert_eq!(packet_buf.as_ptr(), packet.as_ptr());
            state.sent.push(packet_buf.to_vec());
        }
    }

    fn fake_api(state: FakeState) -> Arc<FakeApi> {
        Arc::new(FakeApi(Mutex::new(state)))
    }

    fn packet() -> Packet {
        Packet::new(vec![0; 512].into_boxed_slice(), 0)
    }

    #[test]
    fn config_requires_absolute_path_and_well_formed_sha256() {
        assert!(WintunConfig::new("wintun.dll".into(), &"00".repeat(32)).is_err());
        let temp_dir = TestTempDir::new().expect("create unique temporary directory");
        let dll_path = temp_dir.path().join("wintun.dll");
        assert!(dll_path.is_absolute());
        assert!(WintunConfig::new(dll_path.clone(), "not-a-hash").is_err());
        assert!(WintunConfig::new(dll_path.clone(), &"z".repeat(64)).is_err());
        let config = WintunConfig::new(dll_path.clone(), &"00".repeat(32)).unwrap();
        assert_eq!(config.dll_path, dll_path);
        assert_eq!(config.sha256, [0; 32]);
        temp_dir.cleanup().expect("remove temporary directory");
    }

    #[test]
    fn sha256_pin_comparison_checks_the_exact_contents() {
        let expected = sha256(b"pinned DLL bytes");
        assert!(verify_sha256(&expected, b"pinned DLL bytes"));
        assert!(!verify_sha256(&expected, b"different DLL bytes"));
    }

    #[test]
    fn missing_adapter_fails_without_creating_or_closing_an_adapter() {
        let api = fake_api(FakeState {
            missing_adapter: true,
            ..FakeState::default()
        });
        assert!(Session::open(api.clone(), "missing").is_err());
        assert_eq!(api.0.lock().unwrap().adapter_closes, 0);
    }

    #[test]
    fn adapter_is_closed_if_session_start_fails() {
        let api = fake_api(FakeState {
            fail_start: true,
            ..FakeState::default()
        });
        assert!(Session::open(api.clone(), "existing").is_err());
        let state = api.0.lock().unwrap();
        assert_eq!(state.session_ends, 0);
        assert_eq!(state.adapter_closes, 1);
    }

    #[test]
    fn session_and_adapter_close_if_event_retrieval_fails() {
        let api = fake_api(FakeState {
            fail_event: true,
            ..FakeState::default()
        });
        assert!(Session::open(api.clone(), "existing").is_err());
        let state = api.0.lock().unwrap();
        assert_eq!(state.session_ends, 1);
        assert_eq!(state.adapter_closes, 1);
    }

    #[test]
    fn receive_packets_are_copied_then_released_and_send_packets_are_consumed() {
        let api = fake_api(FakeState {
            incoming: [b"inbound".to_vec().into_boxed_slice()].into(),
            ..FakeState::default()
        });
        let session = Session::open(api.clone(), "existing").unwrap();
        assert_eq!(session.read_wait_event(), 3);
        let mut packets = [packet(), packet()];
        let mut results = Vec::new();
        assert_eq!(session.read_packets(&mut packets, &mut results), 1);
        assert_eq!(packets[0].body(), b"inbound");
        assert_eq!(api.0.lock().unwrap().receive_releases, 1);
        assert!(results[0].as_ref().unwrap() == &7);

        results.clear();
        assert_eq!(session.write_packets(&packets[..1], &mut results), 1);
        assert_eq!(results[0].as_ref().unwrap(), &7);
        assert_eq!(api.0.lock().unwrap().sent, [b"inbound".to_vec()]);
    }

    #[test]
    fn receive_and_send_failures_are_reported_to_the_packet_device_caller() {
        let api = fake_api(FakeState {
            fail_receive: true,
            fail_send: true,
            ..FakeState::default()
        });
        let session = Session::open(api.clone(), "existing").unwrap();
        let mut packets = [packet()];
        packets[0].put_slice(b"outbound");
        let mut results = Vec::new();

        assert_eq!(session.read_packets(&mut packets, &mut results), 1);
        assert_eq!(
            results[0].as_ref().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );

        results.clear();
        assert_eq!(session.write_packets(&packets, &mut results), 1);
        assert_eq!(
            results[0].as_ref().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );

        drop(session);
        let state = api.0.lock().unwrap();
        assert_eq!(state.session_ends, 1);
        assert_eq!(state.adapter_closes, 1);
    }

    #[test]
    fn session_and_adapter_close_once_after_last_session_reference_is_dropped() {
        let api = fake_api(FakeState::default());
        let session = Arc::new(Session::open(api.clone(), "existing").unwrap());
        let first_reference = Arc::clone(&session);
        let second_reference = Arc::clone(&session);
        drop(session);
        assert_eq!(api.0.lock().unwrap().session_ends, 0);
        drop(first_reference);
        assert_eq!(api.0.lock().unwrap().session_ends, 0);
        drop(second_reference);
        let state = api.0.lock().unwrap();
        assert_eq!(state.session_ends, 1);
        assert_eq!(state.adapter_closes, 1);
    }
}
