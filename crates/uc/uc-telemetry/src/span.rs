//! Span context and utilities for distributed tracing.

use opentelemetry::trace::{
    SpanContext as OtelSpanContext, SpanId, TraceFlags, TraceId, TraceState,
};
use serde::{Deserialize, Serialize};

/// Span kind for categorizing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpanKind {
    /// Internal operation.
    #[default]
    Internal,
    /// Server receiving a request.
    Server,
    /// Client making a request.
    Client,
    /// Producer sending a message.
    Producer,
    /// Consumer receiving a message.
    Consumer,
}

impl From<SpanKind> for opentelemetry::trace::SpanKind {
    fn from(kind: SpanKind) -> Self {
        match kind {
            SpanKind::Internal => Self::Internal,
            SpanKind::Server => Self::Server,
            SpanKind::Client => Self::Client,
            SpanKind::Producer => Self::Producer,
            SpanKind::Consumer => Self::Consumer,
        }
    }
}

impl From<opentelemetry::trace::SpanKind> for SpanKind {
    fn from(kind: opentelemetry::trace::SpanKind) -> Self {
        match kind {
            opentelemetry::trace::SpanKind::Internal => Self::Internal,
            opentelemetry::trace::SpanKind::Server => Self::Server,
            opentelemetry::trace::SpanKind::Client => Self::Client,
            opentelemetry::trace::SpanKind::Producer => Self::Producer,
            opentelemetry::trace::SpanKind::Consumer => Self::Consumer,
        }
    }
}

/// Serializable span context for propagation.
///
/// This can be serialized and transmitted in SIP headers for distributed tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanContext {
    /// Trace ID as hex string.
    pub trace_id: String,
    /// Span ID as hex string.
    pub span_id: String,
    /// Trace flags.
    pub flags: u8,
    /// Whether the span is remote.
    pub is_remote: bool,
}

impl SpanContext {
    /// Creates a new span context.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, span_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            flags: 0,
            is_remote: false,
        }
    }

    /// Creates a span context from an OpenTelemetry span context.
    #[must_use]
    pub fn from_otel(ctx: &OtelSpanContext) -> Self {
        Self {
            trace_id: format!("{:032x}", ctx.trace_id()),
            span_id: format!("{:016x}", ctx.span_id()),
            flags: ctx.trace_flags().to_u8(),
            is_remote: ctx.is_remote(),
        }
    }

    /// Converts to an OpenTelemetry span context.
    ///
    /// # Errors
    /// Returns an error if the trace ID or span ID are invalid.
    pub fn to_otel(&self) -> Result<OtelSpanContext, SpanContextError> {
        let trace_id =
            TraceId::from_hex(&self.trace_id).map_err(|_| SpanContextError::InvalidTraceId)?;
        let span_id =
            SpanId::from_hex(&self.span_id).map_err(|_| SpanContextError::InvalidSpanId)?;
        let flags = TraceFlags::new(self.flags);

        Ok(OtelSpanContext::new(
            trace_id,
            span_id,
            flags,
            self.is_remote,
            TraceState::default(),
        ))
    }

    /// Returns true if this context is sampled.
    #[must_use]
    pub fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Sets the sampled flag.
    pub fn set_sampled(&mut self, sampled: bool) {
        if sampled {
            self.flags |= 0x01;
        } else {
            self.flags &= !0x01;
        }
    }

    /// Encodes the span context for W3C Trace Context header.
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.flags)
    }

    /// Decodes a span context from W3C Trace Context header.
    ///
    /// # Errors
    /// Returns an error if the traceparent format is invalid.
    pub fn from_traceparent(traceparent: &str) -> Result<Self, SpanContextError> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 {
            return Err(SpanContextError::InvalidFormat);
        }

        if parts[0] != "00" {
            return Err(SpanContextError::UnsupportedVersion);
        }

        let flags = u8::from_str_radix(parts[3], 16).map_err(|_| SpanContextError::InvalidFlags)?;

        Ok(Self {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            flags,
            is_remote: true,
        })
    }
}

/// Errors that can occur when parsing span contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanContextError {
    /// Invalid format.
    InvalidFormat,
    /// Unsupported version.
    UnsupportedVersion,
    /// Invalid trace ID.
    InvalidTraceId,
    /// Invalid span ID.
    InvalidSpanId,
    /// Invalid flags.
    InvalidFlags,
}

impl std::fmt::Display for SpanContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid traceparent format"),
            Self::UnsupportedVersion => write!(f, "unsupported traceparent version"),
            Self::InvalidTraceId => write!(f, "invalid trace ID"),
            Self::InvalidSpanId => write!(f, "invalid span ID"),
            Self::InvalidFlags => write!(f, "invalid trace flags"),
        }
    }
}

impl std::error::Error for SpanContextError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_context_creation() {
        let ctx = SpanContext::new("00000000000000000000000000000001", "0000000000000001");
        assert_eq!(ctx.trace_id, "00000000000000000000000000000001");
        assert_eq!(ctx.span_id, "0000000000000001");
        assert_eq!(ctx.flags, 0);
        assert!(!ctx.is_remote);
    }

    #[test]
    fn test_traceparent_encoding() {
        let mut ctx = SpanContext::new("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331");
        ctx.set_sampled(true);

        let traceparent = ctx.to_traceparent();
        assert_eq!(
            traceparent,
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        );
    }

    #[test]
    fn test_traceparent_decoding() {
        let traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let ctx = SpanContext::from_traceparent(traceparent).unwrap();

        assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.span_id, "b7ad6b7169203331");
        assert_eq!(ctx.flags, 0x01);
        assert!(ctx.is_remote);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_traceparent_roundtrip() {
        let original = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let ctx = SpanContext::from_traceparent(original).unwrap();
        let encoded = ctx.to_traceparent();
        assert_eq!(encoded, original);
    }

    #[test]
    fn test_invalid_traceparent() {
        assert!(SpanContext::from_traceparent("invalid").is_err());
        assert!(SpanContext::from_traceparent("01-abc-def-00").is_err());
    }

    #[test]
    fn test_sampled_flag() {
        let mut ctx = SpanContext::new("trace", "span");
        assert!(!ctx.is_sampled());

        ctx.set_sampled(true);
        assert!(ctx.is_sampled());

        ctx.set_sampled(false);
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn test_span_kind_conversion() {
        assert_eq!(
            opentelemetry::trace::SpanKind::from(SpanKind::Server),
            opentelemetry::trace::SpanKind::Server
        );
        assert_eq!(
            SpanKind::from(opentelemetry::trace::SpanKind::Client),
            SpanKind::Client
        );
    }
}
