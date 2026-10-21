#![cfg_attr(feature = "ci", deny(warnings))]

pub mod windows_profile;

#[cfg(not(windows))]
include!("lib_unix.inc.rs");

#[cfg(windows)]
#[path = "batch_io_windows.rs"]
pub mod batch_io;
#[cfg(windows)]
pub mod defs;
#[cfg(windows)]
pub mod logging;
#[cfg(windows)]
pub mod main_args;
#[cfg(windows)]
pub mod packet;
#[cfg(windows)]
pub mod sys;
#[cfg(windows)]
pub mod zprtun;
