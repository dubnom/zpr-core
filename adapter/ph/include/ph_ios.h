#ifndef ZPR_PH_IOS_H
#define ZPR_PH_IOS_H

#include <stdint.h>

typedef struct PhIosHandle PhIosHandle;

enum PhIosStatus {
    PH_IOS_STARTING = 0,
    PH_IOS_READY = 1,
    PH_IOS_STOPPED = 2
};

/*
 * Starts adapter mode from an absolute TOML config path and a local Unix
 * datagram socket connected to the host's packet-flow pump.
 *
 * The descriptor is duplicated; the caller retains ownership. The socket must
 * be a SOCK_DGRAM AF_UNIX socket. PacketFd configures the shared open-file
 * description as nonblocking. Startup is asynchronous.
 *
 * Returns NULL on synchronous failure. Read ph_ios_last_error() on the same
 * thread for the error. A non-NULL handle means the worker thread started,
 * not that the node connection is ready.
 */
PhIosHandle *ph_ios_start(const char *config_path, int32_t packet_flow_fd);

/* Returns a PH_IOS_* value. A STOPPED value may represent startup failure. */
uint32_t ph_ios_status(const PhIosHandle *handle);

/*
 * Requests graceful shutdown, waits for the worker, and consumes the handle.
 * Returns 0 on clean shutdown, 1 on startup/runtime failure, or -1 if the
 * worker panicked in a build using unwinding. The current release profile uses
 * panic=abort, so a release panic terminates the process instead.
 */
int32_t ph_ios_stop(PhIosHandle *handle);

/* Thread-local error string; valid until the next FFI call on this thread. */
const char *ph_ios_last_error(void);

#endif
