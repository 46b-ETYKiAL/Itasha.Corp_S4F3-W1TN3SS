//! The onion-connection seam — the **one** place the live Tor dependency enters
//! the send path.
//!
//! [`TorOnionTransport`](crate::TorOnionTransport) does not dial Arti directly;
//! it holds an [`OnionConnector`] and asks it for a duplex byte stream to the
//! onion endpoint. The production [`ArtiConnector`] bootstraps the embedded
//! Arti client (lazily, `OnDemand`) and dials the v3 `.onion`. Because the
//! connector is a trait object, a test can inject an in-memory connector backed
//! by a [`tokio::io::duplex`] pipe — so the entire spool-drain orchestration
//! (retry/backoff bookkeeping, fixed-bucket padding on the wire, the
//! sent/retain/drop accounting) is exercised **offline, with no live `.onion`**.
//! Only the Arti bootstrap+connect itself — genuinely un-mockable without a live
//! Tor network — stays outside the measured surface.
//!
//! Everything downstream of the stream is already transport-agnostic:
//! [`crate::http::post_envelope`] is generic over `AsyncRead + AsyncWrite` and
//! is duplex-tested in its own module. This seam closes the last gap.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use itasha_report_core::backend::SendError;

/// A bidirectional byte stream to the onion service.
///
/// The blanket impl below means **any** `AsyncRead + AsyncWrite + Unpin + Send`
/// type is already an `OnionStream` with no extra code: Arti's `DataStream`, a
/// `tokio::io::DuplexStream`, a TLS stream, … This is the object-safe currency
/// the [`OnionConnector`] hands back.
pub trait OnionStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> OnionStream for T {}

/// A boxed, owned [`OnionStream`] — what a connector yields on success.
pub type BoxedOnionStream = Box<dyn OnionStream>;

/// The boxed future an [`OnionConnector::connect`] returns. Hand-rolled (rather
/// than pulling the `async-trait` proc-macro) to keep the dependency/`cargo-vet`
/// surface minimal — the same rationale that hand-rolls the HTTP client.
pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BoxedOnionStream, SendError>> + Send + 'a>>;

/// The connection seam: open a duplex byte stream to `onion_address:onion_port`.
///
/// Implementors MUST surface only non-identifying errors (no onion address, no
/// circuit details) via [`SendError::Transport`] — the connector is the layer
/// that touches the endpoint, so it is the layer that must not leak it.
pub trait OnionConnector: Send + Sync {
    /// Connect to the onion service and return a ready duplex stream.
    fn connect(&self, onion_address: &str, onion_port: u16) -> ConnectFuture<'_>;
}

/// Opaque handle to the embedded Arti client (kept behind an alias so the
/// public API never leaks Arti types).
type ArtiHandle = arti_client::TorClient<tor_rtcompat::PreferredRuntime>;

/// The production [`OnionConnector`]: an embedded, in-process Arti (pure-Rust
/// Tor) client dialing a v3 `.onion`.
///
/// The client is bootstrapped lazily (`OnDemand`) on the first connect and
/// cached behind an `Arc<Mutex<…>>` so subsequent drains reuse the warm
/// directory consensus. `TorClient` is not `Clone`, hence the shared `Arc`.
#[derive(Clone)]
pub struct ArtiConnector {
    state_dir: PathBuf,
    cache_dir: PathBuf,
    tor: Arc<tokio::sync::Mutex<Option<Arc<ArtiHandle>>>>,
}

impl std::fmt::Debug for ArtiConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtiConnector")
            .field("state_dir", &self.state_dir)
            .field("cache_dir", &self.cache_dir)
            .finish_non_exhaustive()
    }
}

impl ArtiConnector {
    /// Construct the connector rooted at the app's Arti `state`/`cache` dirs.
    /// Persisting these speeds warm bootstraps; they hold the Tor consensus
    /// cache only — never a client identifier.
    #[must_use]
    pub fn new(state_dir: impl Into<PathBuf>, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            cache_dir: cache_dir.into(),
            tor: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Lazily bootstrap (or reuse) the embedded Arti client. The first call
    /// builds it with `OnDemand` bootstrap behaviour; subsequent calls reuse the
    /// cached handle.
    async fn tor_client(&self) -> Result<Arc<ArtiHandle>, SendError> {
        let mut guard = self.tor.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(Arc::clone(client));
        }
        let cfg = build_arti_config(&self.state_dir, &self.cache_dir)?;
        let client = arti_client::TorClient::builder()
            .config(cfg)
            .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
            .create_unbootstrapped()
            .map_err(|e| SendError::Transport(format!("arti init: {}", non_identifying(&e))))?;
        // `create_unbootstrapped` already yields an `Arc<TorClient>`.
        *guard = Some(Arc::clone(&client));
        Ok(client)
    }
}

impl OnionConnector for ArtiConnector {
    fn connect(&self, onion_address: &str, onion_port: u16) -> ConnectFuture<'_> {
        // The address is owned into the future so its lifetime is independent of
        // the caller's borrow once `connect` returns.
        let addr = onion_address.to_string();
        Box::pin(async move {
            let client = self.tor_client().await?;
            let stream = client
                .connect((addr.as_str(), onion_port))
                .await
                .map_err(|e| {
                    SendError::Transport(format!("onion connect: {}", non_identifying(&e)))
                })?;
            Ok(Box::new(stream) as BoxedOnionStream)
        })
    }
}

/// Build the Arti `TorClientConfig` pointing storage at the app's state/cache
/// dirs. Persisting the consensus cache makes warm bootstraps fast.
fn build_arti_config(
    state_dir: &Path,
    cache_dir: &Path,
) -> Result<arti_client::TorClientConfig, SendError> {
    arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .map_err(|e| SendError::Transport(format!("arti config: {}", non_identifying(&e))))
}

/// Reduce an arbitrary error to a non-identifying single-line string (no URLs,
/// no host, no onion address). Keeps the error *class* for diagnostics without
/// leaking the endpoint.
pub(crate) fn non_identifying<E: std::fmt::Display>(_e: &E) -> &'static str {
    // We deliberately do NOT format the error: Arti errors can embed the onion
    // address / circuit details. The transport surfaces a class only.
    "tor transport error"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_identifying_never_leaks_input() {
        let s = non_identifying(&"connect to abcd1234.onion failed");
        assert_eq!(s, "tor transport error");
        assert!(!s.contains("onion"));
    }

    #[test]
    fn arti_connector_debug_does_not_leak_endpoint() {
        let c = ArtiConnector::new("/tmp/state", "/tmp/cache");
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ArtiConnector"));
        // The connector holds no onion address — it is supplied per-connect.
        assert!(!dbg.contains(".onion"));
    }

    #[test]
    fn build_arti_config_accepts_dirs() {
        let dir = std::env::temp_dir().join("w1tn3ss-arti-cfg-test");
        let cfg = build_arti_config(&dir.join("state"), &dir.join("cache"));
        assert!(cfg.is_ok());
    }
}
