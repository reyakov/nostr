// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Runtime abstraction for async runtimes.
//!
//! This module provides a [`Runtime`] trait that abstracts
//! runtime-specific functionality (TCP, spawning, timers) so the
//! proxy can work with any async runtime.

use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
#[cfg(not(feature = "tokio"))]
use std::pin::Pin;
use std::time::Duration;

/// Abstraction over async runtime primitives needed by the proxy.
pub trait Runtime: Debug + Clone + Send + Sync + 'static {
    /// I/O type that implements hyper's read/write traits.
    type Io: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static;

    /// Bind a TCP listener to `addr`.
    fn bind(addr: SocketAddr) -> impl Future<Output = io::Result<Self>> + Send;

    /// Accept an incoming TCP connection.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Io, SocketAddr)>> + Send;

    /// Spawn a background task.
    fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static);

    /// Sleep for the given duration.
    fn sleep(dur: Duration) -> impl Future<Output = ()> + Send;
}

#[cfg(feature = "tokio")]
mod tokio_impl {
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use hyper_util::rt::TokioIo;

    use super::Runtime;

    /// Tokio-based runtime implementation.
    #[derive(Debug, Clone)]
    pub struct TokioRuntime {
        listener: Arc<tokio::net::TcpListener>,
    }

    impl Runtime for TokioRuntime {
        type Io = TokioIo<tokio::net::TcpStream>;

        async fn bind(addr: SocketAddr) -> io::Result<Self> {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            Ok(Self {
                listener: Arc::new(listener),
            })
        }

        async fn accept(&self) -> io::Result<(Self::Io, SocketAddr)> {
            let (stream, addr) = self.listener.accept().await?;
            Ok((TokioIo::new(stream), addr))
        }

        fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static) {
            tokio::spawn(fut);
        }

        async fn sleep(dur: Duration) {
            tokio::time::sleep(dur).await;
        }
    }
}

#[cfg(feature = "tokio")]
pub use tokio_impl::TokioRuntime;

/// Stub runtime implementation for when no runtime feature is enabled.
///
/// This runtime cannot actually serve connections — it exists purely so the
/// crate compiles without a runtime feature. Enable the `tokio` feature (on by
/// default) for a working runtime.
#[cfg(not(feature = "tokio"))]
#[derive(Debug, Clone)]
pub struct NoRuntime;

#[cfg(not(feature = "tokio"))]
impl Runtime for NoRuntime {
    /// Use a pinned, boxed dynamic I/O type that satisfies the bounds
    /// without requiring a concrete runtime-specific type.
    type Io = Pin<Box<dyn hyper::rt::Read + hyper::rt::Write + Send + 'static>>;

    async fn bind(_addr: SocketAddr) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "no runtime configured; enable the `tokio` feature",
        ))
    }

    async fn accept(&self) -> io::Result<(Self::Io, SocketAddr)> {
        unreachable!("NoRuntime cannot bind")
    }

    fn spawn(&self, _fut: impl Future<Output = ()> + Send + 'static) {
        panic!("no runtime configured; enable the `tokio` feature")
    }

    async fn sleep(_dur: Duration) {}
}
