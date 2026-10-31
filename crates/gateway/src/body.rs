//! The response body the guest receives: the provider's bytes, unchanged,
//! with usage read off a copy as they pass. Usage is booked exactly once,
//! when the body ends or when it is dropped early (client gone, upstream cut
//! off): the provider bills for what it generated either way.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};

use crate::usage::UsageScanner;
use crate::BoxError;

/// Called once with the usage seen and whether the body ended normally.
pub type OnFinish = Box<dyn FnOnce(Option<sodabox_common::event::Tokens>, bool) + Send>;

pub struct MeteredBody {
    inner: Pin<Box<dyn Body<Data = Bytes, Error = BoxError> + Send>>,
    scanner: UsageScanner,
    on_finish: Option<OnFinish>,
}

impl MeteredBody {
    pub fn new<B>(inner: B, scanner: UsageScanner, on_finish: OnFinish) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        use http_body_util::BodyExt;
        Self {
            inner: Box::pin(inner.map_err(Into::into)),
            scanner,
            on_finish: Some(on_finish),
        }
    }

    fn finish(&mut self, complete: bool) {
        if let Some(f) = self.on_finish.take() {
            f(self.scanner.finish(), complete);
        }
    }
}

impl Body for MeteredBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.scanner.feed(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.finish(false);
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.finish(true);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for MeteredBody {
    fn drop(&mut self) {
        // hyper stops polling once `is_end_stream` says the body is done, so a
        // fully sent body can be dropped without ever returning `None`.
        // Anything else is a response cut short (e.g. the client went away).
        let complete = self.inner.is_end_stream();
        self.finish(complete);
    }
}
