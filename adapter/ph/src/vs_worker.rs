use std::net::{IpAddr, SocketAddr};
use tokio::sync::broadcast;

use crate::prelude::*;
use crate::visa_mgmt;
use crate::vss_worker;

use libnode::error::VSApiError;
use libnode::vsconn::{NodeConnect, StateFlag, VSConnHandle, VSConnLifecycleEvent};
use zpr::vsapi_types::ErrorCode;

pub async fn launch(
    asm: Arc<Assembly>,
    node_zpr_addr: IpAddr,
    vss_addr: SocketAddr,
    vs_handle: VSConnHandle,
    mut lifecycle_rx: broadcast::Receiver<VSConnLifecycleEvent>,
) {
    // When launched, we have no state with the VS.
    let mut state = StateFlag::NoState;

    //derive pubkey from a2a_dh_keypair
    let a2a_dh_pubkey = x25519_dalek::PublicKey::from(&asm.a2a_dh_keypair);

    // TODO: The new visa service supports a "reconnect" signal. That is not yet exposed by libnode2
    loop {
        // This acts as a gate -- waiting for runloop to start.
        if !wait_for_runloop_start(&mut lifecycle_rx).await {
            return;
        }

        let mut connected = false;
        loop {
            // Kick off a connect request to the VS, if it succeeds, notify the VS about our VSS endpoint.
            let req = NodeConnect {
                zpr_addr: node_zpr_addr,
                state,
                a2a_dh_pubkey,
            };

            if !connected {
                connected = match wait_for_connect(vs_handle.connect(req), &mut lifecycle_rx).await
                {
                    Some(res) => match res {
                        Ok(()) => {
                            info!(target: STARTUP, "node access granted to visa service");
                            true
                        }
                        Err(VSApiError::CodedError(err))
                            if matches!(err.code, ErrorCode::OutOfSync) =>
                        {
                            state = StateFlag::NoState;
                            info!(target: STARTUP, "visa service reports out-of-sync; clearing adapters and visas");
                            asm.disconnect_adapters().await; // drops visas too
                            false
                        }
                        Err(e) => {
                            error!(target: STARTUP, "failed to get access to visa service: {e:?}");
                            false
                        }
                    },
                    None => break,
                };
            }

            if connected {
                // VSS initialization needs the VS adapter registered as a flow source.
                let deferred = asm.deferred_vs_connect.lock().unwrap().take();
                if let Some((vs_link_id, assigned_addr, conn_req)) = deferred {
                    if let Err(e) = visa_mgmt::send_deferred_vs_connect(
                        &asm,
                        vs_link_id,
                        assigned_addr,
                        conn_req,
                    )
                    .await
                    {
                        error!(target: STARTUP, "{}: deferred visa service adapter connect failed: {e}",
                            asm.formatted_link_id(vs_link_id));
                        if let Err(link_error) = asm.process_link_state_event(
                            vs_link_id,
                            crate::link_state::LinkEvent::Error,
                        ) {
                            error!(target: STARTUP, "failed to restart VS adapter link after registration error: {link_error}");
                        }

                        tokio::time::sleep(config::VSCONN_RETRY_WAIT).await;
                        continue;
                    }
                }
                asm.report_active_node_link_statuses().await;
                match vs_handle.register_vss(vss_addr).await {
                    Ok(ops) => {
                        info!(target: STARTUP, "registered VSS, received {} pending visa ops", ops.len());
                        for op in ops {
                            if let Err(e) = vss_worker::process_visaop(&asm, op) {
                                error!(target: STARTUP, "failed to process initial visa op from VS: {e:?}");
                            }
                        }

                        // Next time we connect, we have state.
                        state = StateFlag::HasState;
                        break; // Exit inner loop; go back to waiting for a state change.
                    }
                    Err(e) => {
                        error!(target: STARTUP, "failed to register VSS: {e:?}");

                        if matches!(e, VSApiError::ConnClosed) {
                            break;
                        }
                    }
                }
            }

            // wait a second and retry.
            tokio::time::sleep(config::VSCONN_RETRY_WAIT).await;
        }
    }
}

async fn wait_for_connect(
    connect: impl std::future::Future<Output = Result<(), VSApiError>>,
    lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>,
) -> Option<Result<(), VSApiError>> {
    tokio::pin!(connect);
    loop {
        tokio::select! {
            res = &mut connect => return Some(res),
            evt = lifecycle_rx.recv() => match evt {
                Ok(VSConnLifecycleEvent::RunLoopExits) => return None,
                Ok(_) => {},
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                    return Some(Err(VSApiError::ConnClosed));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lifecycle_notifications_do_not_cancel_in_flight_connect() {
        let (tx, mut rx) = broadcast::channel(4);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tx.send(VSConnLifecycleEvent::RunLoopStarts).unwrap();
        tx.send(VSConnLifecycleEvent::ConnectedToVsApi(StateFlag::NoState))
            .unwrap();
        let connect = async move {
            done_rx.await.unwrap();
            Ok(())
        };
        let wait = wait_for_connect(connect, &mut rx);
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut wait)
                .await
                .is_err()
        );
        done_tx.send(()).unwrap();
        assert!(matches!(wait.await, Some(Ok(()))));
    }

    #[tokio::test]
    async fn runloop_exit_aborts_pending_connect() {
        let (tx, mut rx) = broadcast::channel(4);
        tx.send(VSConnLifecycleEvent::RunLoopExits).unwrap();
        assert!(
            wait_for_connect(std::future::pending(), &mut rx)
                .await
                .is_none()
        );
    }
}

async fn wait_for_runloop_start(
    lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>,
) -> bool {
    loop {
        match lifecycle_rx.recv().await {
            Ok(VSConnLifecycleEvent::RunLoopStarts) => return true,
            Ok(_) => {
                // ignored
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
                continue; // try again
            }
            Err(broadcast::error::RecvError::Closed) => {
                error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                return false;
            }
        }
    }
}
