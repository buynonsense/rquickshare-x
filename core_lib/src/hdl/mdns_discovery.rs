use std::collections::HashMap;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use ts_rs::TS;

use crate::utils::{is_not_self_ip, parse_mdns_endpoint_info};
use crate::DeviceType;

/// Wait this long after a `ServiceRemoved` before actually removing the
/// device from the cache and notifying the frontend. mDNS can deliver
/// transient `ServiceRemoved` events (missed TTL refresh, multicast loss)
/// even when the peer is still broadcasting, so we keep the entry around
/// for a short window in case a follow-up `ServiceResolved` arrives.
const REMOVAL_GRACE: Duration = Duration::from_secs(5);
/// How often the cleanup tick wakes up to expire stale pending removals.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Default, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct EndpointInfo {
    pub fullname: String,
    pub id: String,
    pub name: Option<String>,
    pub ip: Option<String>,
    pub port: Option<String>,
    pub rtype: Option<DeviceType>,
    pub present: Option<bool>,
}

pub struct MDnsDiscovery {
    daemon: ServiceDaemon,
    sender: broadcast::Sender<EndpointInfo>,
}

impl MDnsDiscovery {
    pub fn new(sender: broadcast::Sender<EndpointInfo>) -> Result<Self, anyhow::Error> {
        let daemon = ServiceDaemon::new()?;

        Ok(Self { daemon, sender })
    }

    pub async fn run(self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("MDnsDiscovery: service starting");

        let service_type = "_FC9F5ED42C8A._tcp.local.";
        let receiver = self.daemon.browse(service_type)?;

        // Primary store, keyed by the stable endpoint id (`ip:port`) so
        // re-registrations from the same peer collapse onto one entry
        // instead of looking like a different device. mDNS instance
        // names (`fullname`) are not stable across network changes on
        // some third-party Quick Share implementations (e.g. Bada
        // regenerates the 4-byte random endpoint id on every
        // `advertise()`), but `ip:port` only changes when the peer's
        // socket actually moves.
        let mut entries: HashMap<String, EndpointInfo> = HashMap::new();
        // fullname -> id, used to map a `ServiceRemoved(fullname)` back
        // to the right cache entry. Cleaned up on resolve and on the
        // grace-period tick.
        let mut fullname_index: HashMap<String, String> = HashMap::new();
        // id -> Instant: ids whose latest `ServiceResolved` has been
        // followed by a matching `ServiceRemoved` and are waiting out
        // the grace period. Re-resolving the same id (even under a new
        // fullname) cancels the pending removal.
        let mut pending_removal: HashMap<String, Instant> = HashMap::new();
        let mut cleanup = tokio::time::interval(CLEANUP_INTERVAL);
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("MDnsDiscovery: tracker cancelled, breaking");
                    break;
                }
                _ = cleanup.tick() => {
                    // Expire pending removals whose grace window has passed.
                    let now = Instant::now();
                    let expired: Vec<String> = pending_removal
                        .iter()
                        .filter(|(_, t)| now.duration_since(**t) >= REMOVAL_GRACE)
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in expired {
                        pending_removal.remove(&id);
                        fullname_index.retain(|_, v| v != &id);
                        // Only notify the frontend if the entry is still
                        // the one we marked for removal. A re-resolve
                        // that updated the entry would have cancelled
                        // `pending_removal[id]` already, so the only
                        // path that lands here with entries.remove ==
                        // None is a defensive guard against double-fire.
                        if entries.remove(&id).is_some() {
                            info!(
                                "MDnsDiscovery: grace period expired, removing endpoint id: {}",
                                id
                            );
                            let _ = self.sender.send(EndpointInfo {
                                id,
                                ..Default::default()
                            });
                        }
                    }
                }
                r = receiver.recv_async() => {
                    match r {
                        Ok(event) => {
                            match event {
                                ServiceEvent::ServiceResolved(info) => {
                                    let port = info.get_port();

                                    let ip_hash = info.get_addresses_v4();
                                    if ip_hash.is_empty() {
                                        continue;
                                    }

                                    let ip = match ip_hash.iter().next() {
                                        Some(i) => i,
                                        None => continue,
                                    };

                                    // Check that the IP is not a "self IP"
                                    if !is_not_self_ip(ip) {
                                        continue;
                                    }

                                    // Decode the "n" text properties
                                    let n = match info.get_property("n") {
                                        Some(_n) => _n,
                                        None => continue,
                                    };

                                    // Parse the endpoint info
                                    let (dt, dn) = match parse_mdns_endpoint_info(n.val_str()) {
                                        Ok(r) => r,
                                        Err(_) => continue
                                    };

                                    let ip_port = format!("{ip}:{port}");
                                    let fullname = info.get_fullname().to_string();
                                    if TcpStream::connect(&ip_port).await.is_ok() {
                                        let ei = EndpointInfo {
                                            fullname: fullname.clone(),
                                            id: ip_port.clone(),
                                            name: Some(dn),
                                            ip: Some(ip.to_string()),
                                            port: Some(port.to_string()),
                                            rtype: Some(dt),
                                            present: Some(true),
                                        };
                                        info!("ServiceResolved: Resolved a new service: {:?}", ei);
                                        entries.insert(ip_port.clone(), ei.clone());
                                        fullname_index.insert(fullname, ip_port.clone());
                                        // A re-resolve with the same
                                        // `ip:port` means the previous
                                        // ServiceRemoved was spurious
                                        // (or the peer re-announced
                                        // after a network change with
                                        // a fresh mDNS instance name).
                                        // Cancel any pending removal
                                        // keyed by this id.
                                        if pending_removal.remove(&ip_port).is_some() {
                                            debug!(
                                                "MDnsDiscovery: pending removal cancelled for id {}",
                                                ip_port
                                            );
                                        }
                                        let _ = self.sender.send(ei);
                                    }
                                }
                                ServiceEvent::ServiceRemoved(_, fullname) => {
                                    trace!("ServiceRemoved: checking if should remove {}", fullname);
                                    // Map the disappearing fullname back
                                    // to its id and start the grace
                                    // countdown. The entry stays in
                                    // `entries` so a re-resolve under a
                                    // different fullname (same id) can
                                    // cancel the removal.
                                    if let Some(id) = fullname_index.remove(&fullname) {
                                        info!(
                                            "ServiceRemoved: scheduling removal for id {} (fullname={}) after {:?}",
                                            id, fullname, REMOVAL_GRACE
                                        );
                                        pending_removal.insert(id, Instant::now());
                                    }
                                }
                                ServiceEvent::SearchStarted(_) | ServiceEvent::SearchStopped(_) => {}
                                _ => {}
                            }
                        },
                        Err(err) => error!("MDnsDiscovery: error: {}", err),
                    }
                }
            }
        }

        Ok(())
    }
}
