//! The connections tonic serves, with who made them.

use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::UnixStream;
use tonic::transport::server::Connected;

use crate::authorization::Caller;

/// An accepted connection, which tonic serves with its caller `C` in each request's extensions
/// (a [`Caller`] here, serviced's own for its API).
#[derive(Debug)]
pub struct CallerStream<C = Caller> {
    stream: UnixStream,
    caller: C,
}

impl<C> CallerStream<C> {
    /// `stream`, of `caller`.
    #[must_use]
    pub fn new(stream: UnixStream, caller: C) -> Self {
        Self { stream, caller }
    }
}

impl<C: Clone + Send + Sync + 'static> Connected for CallerStream<C> {
    type ConnectInfo = C;

    fn connect_info(&self) -> C {
        self.caller.clone()
    }
}

impl<C: Unpin> AsyncRead for CallerStream<C> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<C: Unpin> AsyncWrite for CallerStream<C> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}
