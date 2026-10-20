# Vendored capnproto-rust crates

These four crates are copied from
[`emilazy/capnproto-rust`](https://github.com/emilazy/capnproto-rust) at
revision `cfbcb9bf2b620db96cffdfd4bb09af4837093bab`:
`capnp`, `capnp-futures`, `capnp-rpc`, and `capnpc`.

The upstream MIT license is included in `UPSTREAM-LICENSE` and in each crate
directory. The vendored workspace metadata retains the upstream Rust version
and lint settings.

The only source change is in `capnp/src/fd/compat.rs`: its non-Unix
`BorrowedFd` placeholder uses a hidden `Infallible` marker to give the
lifetime parameter a valid name while keeping the type uninhabited. Its
`AsFd` implementations now handle references to those placeholders
exhaustively. The Unix FD implementation is unchanged.
