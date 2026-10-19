use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use nix::poll::{self, PollFd, PollFlags, PollTimeout};

#[derive(Clone)]
pub struct ReadinessSource(Arc<OwnedFd>);

impl ReadinessSource {
    pub(crate) fn from_fd(fd: &impl AsFd) -> io::Result<Self> {
        Ok(Self(Arc::new(fd.as_fd().try_clone_to_owned()?)))
    }

    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

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

pub fn wait<const N: usize>(
    requests: [ReadinessRequest<'_>; N],
    timeout_millis: Option<u16>,
) -> io::Result<[ReadinessEvents; N]> {
    let mut poll_fds: [PollFd<'_>; N] = std::array::from_fn(|index| {
        let request = &requests[index];
        let mut flags = PollFlags::empty();
        if request.interest.readable {
            flags |= PollFlags::POLLIN;
        }
        if request.interest.writable {
            flags |= PollFlags::POLLOUT;
        }
        PollFd::new(request.source.as_fd(), flags)
    });

    loop {
        let timeout = timeout_millis
            .map(PollTimeout::from)
            .unwrap_or(PollTimeout::NONE);
        match poll::poll(&mut poll_fds, timeout) {
            Ok(_) => {
                return Ok(std::array::from_fn(|index| {
                    let flags = poll_fds[index].revents().unwrap();
                    ReadinessEvents {
                        readable: flags.contains(PollFlags::POLLIN),
                        writable: flags.contains(PollFlags::POLLOUT),
                    }
                }));
            }
            Err(error) if error == nix::errno::Errno::EINTR => continue,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::posix::notify::Notify;

    #[test]
    fn wait_reports_readiness_without_exposing_file_descriptors() {
        let notify = Notify::new().unwrap();
        let source = notify.readiness_source().clone();
        std::thread::spawn(move || {
            notify.post();
        });

        let events = wait(
            [ReadinessRequest {
                source: &source,
                interest: ReadinessInterest::new(true, false),
            }],
            None,
        )
        .unwrap();

        assert_eq!(
            events[0],
            ReadinessEvents {
                readable: true,
                writable: false,
            }
        );
    }
}
