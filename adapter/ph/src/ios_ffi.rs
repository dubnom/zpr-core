use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::path::Path;

pub const PH_IOS_STARTING: u32 = 0;
pub const PH_IOS_READY: u32 = 1;
pub const PH_IOS_STOPPED: u32 = 2;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn parse_config_path(config_path: &CStr) -> Result<String, &'static str> {
    let config_path = config_path
        .to_str()
        .map_err(|_| "configuration path must be valid UTF-8")?;
    if config_path.is_empty() || !Path::new(config_path).is_absolute() {
        return Err("configuration path must be an absolute path");
    }
    Ok(config_path.to_owned())
}

fn set_last_error(message: &str) {
    let message = message.replace('\0', "\\0");
    LAST_ERROR.with(|last_error| {
        *last_error.borrow_mut() = CString::new(message).unwrap_or_default();
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|last_error| *last_error.borrow_mut() = CString::default());
}

#[cfg(target_os = "ios")]
struct PhIosHandle {
    stop: tokio_util::sync::CancellationToken,
    status: std::sync::Arc<std::sync::atomic::AtomicU8>,
    exit_code: std::sync::Arc<std::sync::atomic::AtomicI32>,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "ios")]
fn start(config_path: &CStr, packet_flow_fd: i32) -> Result<*mut PhIosHandle, String> {
    use std::os::fd::BorrowedFd;
    use std::sync::atomic::{AtomicI32, AtomicU8};
    use std::sync::{Arc, atomic::Ordering};
    use tokio_util::sync::CancellationToken;

    let config_path = parse_config_path(config_path).map_err(str::to_owned)?;
    if packet_flow_fd < 0 {
        return Err("packet-flow descriptor must be non-negative".to_owned());
    }

    let packet_flow_fd = unsafe {
        // SAFETY: the caller guarantees that packet_flow_fd is an open descriptor during this call.
        BorrowedFd::borrow_raw(packet_flow_fd)
    };
    let packet_device = crate::sys::ios::ZprTun::from_packet_fd(
        packet_flow_fd
            .try_clone_to_owned()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    let stop = CancellationToken::new();
    let worker_stop = stop.clone();
    let status = Arc::new(AtomicU8::new(PH_IOS_STARTING as u8));
    let worker_status = Arc::clone(&status);
    let exit_code = Arc::new(AtomicI32::new(-1));
    let worker_exit_code = Arc::clone(&exit_code);
    let args = vec![
        "ph".to_owned(),
        "adapter".to_owned(),
        "--config".to_owned(),
        config_path,
    ];
    let worker = std::thread::Builder::new()
        .name("zpr-ph-ios".to_owned())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::runner::run_with_ios_packet_device(
                    args,
                    worker_stop,
                    packet_device,
                    worker_status.clone(),
                )
            }));
            let code = match result {
                Ok(code) if code == std::process::ExitCode::SUCCESS => 0,
                Ok(_) => 1,
                Err(_) => -1,
            };
            worker_exit_code.store(code, Ordering::Release);
            worker_status.store(PH_IOS_STOPPED as u8, Ordering::Release);
        })
        .map_err(|error| error.to_string())?;

    Ok(Box::into_raw(Box::new(PhIosHandle {
        stop,
        status,
        exit_code,
        worker: Some(worker),
    })))
}

/// Starts adapter mode with a local Unix datagram socket supplied by the host.
///
/// The descriptor is duplicated and the caller retains ownership. The socket
/// must be the packet-flow side of a local datagram socket pair. Startup is
/// asynchronous; query `ph_ios_status` until it reports ready or stopped.
///
/// # Safety
/// `config_path` must point to a valid NUL-terminated C string for this call,
/// and `packet_flow_fd` must be an open descriptor for this call.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ph_ios_start(
    config_path: *const std::ffi::c_char,
    packet_flow_fd: i32,
) -> *mut std::ffi::c_void {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if config_path.is_null() {
            return Err("configuration path pointer must not be null".to_owned());
        }
        let config_path = unsafe {
            // SAFETY: the caller guarantees a valid NUL-terminated C string.
            CStr::from_ptr(config_path)
        };
        start(config_path, packet_flow_fd)
    }));
    match result {
        Ok(Ok(handle)) => {
            clear_last_error();
            handle.cast()
        }
        Ok(Err(error)) => {
            set_last_error(&error);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic while starting the iOS packet handler");
            std::ptr::null_mut()
        }
    }
}

/// Returns a `PH_IOS_*` status value for a live handle.
///
/// # Safety
/// `handle` must be a live pointer returned by `ph_ios_start` and must not be
/// used concurrently with `ph_ios_stop`.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ph_ios_status(handle: *const std::ffi::c_void) -> u32 {
    if handle.is_null() {
        set_last_error("packet-handler handle must not be null");
        return PH_IOS_STOPPED;
    }
    let handle = unsafe {
        // SAFETY: the caller guarantees that handle is live and not concurrently stopped.
        &*handle.cast::<PhIosHandle>()
    };
    clear_last_error();
    u32::from(handle.status.load(std::sync::atomic::Ordering::Acquire))
}

/// Cancels and joins the packet handler, then consumes its handle.
///
/// Returns zero after clean shutdown, one after a startup/runtime failure, or
/// minus one if the worker panicked in a build using unwinding. The current
/// release profile uses `panic=abort`, so a release panic terminates the process.
///
/// # Safety
/// `handle` must be a live pointer returned by `ph_ios_start` and may be
/// consumed exactly once.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ph_ios_stop(handle: *mut std::ffi::c_void) -> i32 {
    if handle.is_null() {
        set_last_error("packet-handler handle must not be null");
        return -1;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut handle = unsafe {
            // SAFETY: the caller guarantees this live handle is consumed exactly once.
            Box::from_raw(handle.cast::<PhIosHandle>())
        };
        handle.stop.cancel();
        match handle
            .worker
            .take()
            .expect("worker handle is present")
            .join()
        {
            Ok(()) => {
                clear_last_error();
                handle.exit_code.load(std::sync::atomic::Ordering::Acquire)
            }
            Err(_) => {
                set_last_error("packet-handler worker thread panicked");
                -1
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_last_error("panic while stopping the iOS packet handler");
        -1
    })
}

/// Returns the last synchronous FFI error for the calling thread, or an empty
/// string when the previous call succeeded.
///
/// The pointer remains valid until the next FFI call on the same thread.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn ph_ios_last_error() -> *const std::ffi::c_char {
    LAST_ERROR.with(|last_error| last_error.borrow().as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn configuration_path_must_be_absolute_and_utf8() {
        assert_eq!(
            parse_config_path(&CString::new("/group/zpr/adapter.toml").unwrap()),
            Ok("/group/zpr/adapter.toml".to_owned())
        );
        assert!(parse_config_path(&CString::new("adapter.toml").unwrap()).is_err());
        assert!(parse_config_path(&CString::new("").unwrap()).is_err());
    }

    #[test]
    fn errors_are_safe_to_store_as_c_strings() {
        set_last_error("invalid\0message");
        LAST_ERROR.with(|last_error| {
            assert_eq!(last_error.borrow().to_str().unwrap(), "invalid\\0message");
        });
        clear_last_error();
        LAST_ERROR.with(|last_error| assert_eq!(last_error.borrow().as_bytes(), b""));
    }
}
