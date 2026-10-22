// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Risk Guard as the decision point for an egress proxy that Envoy's external authorization protocol can reach.
//!
//! The enforcement point is then a proxy on the network path, not the supervisor inside the workload: the workload connects to
//! the proxy with its X.509-SVID, the proxy verifies it (so it knows the caller by network identity, which the workload cannot
//! fake), and asks Risk Guard `Check` for every request. Risk Guard answers allow or deny; the proxy forwards or returns 403.
//!
//! Two identities are in play, and they are kept apart:
//!
//! * the **proxy** authenticates to Risk Guard with its own SVID over mutual TLS. Only SPIFFE IDs the operator lists with
//!   `--svid-proxy-id` may call `Check`, because a proxy is trusted to say who the downstream caller is;
//! * the **workload** is the caller the proxy verified, passed in `source.principal`. It becomes a Risk Guard workload exactly as
//!   on the SVID listener.
//!
//! Only the method, host and path are used. Headers, query strings and bodies are ignored, as everywhere else in Risk Guard.
//! The message types below are the subset of `envoy.service.auth.v3` this needs (protobuf ignores fields it does not know),
//! so no Envoy code is a dependency.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tonic::codegen::{Body, BoxFuture, StdError, http};

use crate::spiffe::{SpiffeId, SvidEnroller, SvidPolicy, peer_from_metadata};
use crate::types::{
    DecisionOutcome, NativeObservationSource, RawRequestInput, RequestNormalizer, RiskDetector,
    RiskStore,
};

#[derive(Clone, PartialEq, prost::Message)]
pub struct CheckRequest {
    #[prost(message, optional, tag = "1")]
    pub attributes: Option<AttributeContext>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AttributeContext {
    #[prost(message, optional, tag = "1")]
    pub source: Option<Peer>,
    #[prost(message, optional, tag = "4")]
    pub request: Option<AttributeRequest>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Peer {
    #[prost(string, tag = "2")]
    pub service: String,
    /// The URI SAN of the peer's certificate, which for an SVID is its SPIFFE ID.
    #[prost(string, tag = "4")]
    pub principal: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AttributeRequest {
    #[prost(message, optional, tag = "2")]
    pub http: Option<HttpRequest>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HttpRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub method: String,
    #[prost(string, tag = "4")]
    pub path: String,
    #[prost(string, tag = "5")]
    pub host: String,
    #[prost(string, tag = "6")]
    pub scheme: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CheckResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<RpcStatus>,
    #[prost(message, optional, tag = "2")]
    pub denied_response: Option<DeniedHttpResponse>,
    #[prost(message, optional, tag = "3")]
    pub ok_response: Option<OkHttpResponse>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RpcStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeniedHttpResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<HttpStatus>,
    #[prost(string, tag = "3")]
    pub body: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HttpStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct OkHttpResponse {}

const GRPC_OK: i32 = 0;
const GRPC_PERMISSION_DENIED: i32 = 7;
const HTTP_FORBIDDEN: i32 = 403;
const EVALUATION_TIMEOUT: Duration = Duration::from_millis(500);

fn allow() -> CheckResponse {
    CheckResponse {
        status: Some(RpcStatus {
            code: GRPC_OK,
            message: String::new(),
        }),
        denied_response: None,
        ok_response: Some(OkHttpResponse {}),
    }
}

fn deny(reason: &str) -> CheckResponse {
    CheckResponse {
        status: Some(RpcStatus {
            code: GRPC_PERMISSION_DENIED,
            message: reason.to_string(),
        }),
        denied_response: Some(DeniedHttpResponse {
            status: Some(HttpStatus {
                code: HTTP_FORBIDDEN,
            }),
            body: format!("denied by Risk Guard: {reason}\n"),
        }),
        ok_response: None,
    }
}

/// Split `host[:port]` and default the port from the scheme.
fn host_and_port(host: &str, scheme: &str) -> (String, u16) {
    let default = if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    };
    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') => match port.parse::<u16>() {
            Ok(port) => (name.to_string(), port),
            Err(_) => (host.to_string(), default),
        },
        _ => (host.to_string(), default),
    }
}

/// Answers Envoy `Check` calls from trusted proxies by scoring the request as the downstream workload.
#[derive(Clone)]
pub struct ExtAuthzService {
    store: Arc<dyn RiskStore>,
    normalizer: Arc<dyn RequestNormalizer>,
    detector: Arc<dyn RiskDetector>,
    enroller: Arc<SvidEnroller>,
    workload_policy: SvidPolicy,
    proxies: Arc<BTreeSet<String>>,
}

impl ExtAuthzService {
    pub fn new(
        store: Arc<dyn RiskStore>,
        normalizer: Arc<dyn RequestNormalizer>,
        detector: Arc<dyn RiskDetector>,
        enroller: Arc<SvidEnroller>,
        workload_policy: SvidPolicy,
        proxy_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> crate::error::Result<Self> {
        let mut proxies = BTreeSet::new();
        for id in proxy_ids {
            proxies.insert(SpiffeId::parse(id.as_ref().trim())?.uri());
        }
        if proxies.is_empty() {
            return Err(crate::error::RiskGuardError::InvalidArgument(
                "external authorization needs at least one trusted proxy (--svid-proxy-id)".into(),
            ));
        }
        Ok(Self {
            store,
            normalizer,
            detector,
            enroller,
            workload_policy,
            proxies: Arc::new(proxies),
        })
    }

    #[must_use]
    pub fn into_server(self) -> AuthorizationServer {
        AuthorizationServer { service: self }
    }

    async fn check(
        &self,
        request: tonic::Request<CheckRequest>,
    ) -> std::result::Result<CheckResponse, tonic::Status> {
        // Who is asking: a proxy the operator trusts, proven by its certificate.
        let proxy = peer_from_metadata(&self.workload_policy, request.metadata())
            .map_err(|error| tonic::Status::unauthenticated(error.to_string()))?;
        if !self.proxies.contains(&proxy.uri()) {
            return Err(tonic::Status::permission_denied(format!(
                "{} is not a trusted proxy",
                proxy.uri()
            )));
        }

        let attributes = request.into_inner().attributes.unwrap_or_default();
        let http = attributes
            .request
            .and_then(|request| request.http)
            .ok_or_else(|| tonic::Status::invalid_argument("the check carries no HTTP request"))?;

        // Who is calling: the workload the proxy verified. With no verified SPIFFE identity there is nobody to score.
        let principal = attributes
            .source
            .map(|peer| peer.principal)
            .unwrap_or_default();
        let Ok(workload) = SpiffeId::parse(&principal) else {
            return Ok(deny("the caller has no verified SPIFFE identity"));
        };
        if self.workload_policy.authorize(&workload).is_err() {
            return Ok(deny("the caller's trust domain is not accepted"));
        }

        let enroller = Arc::clone(&self.enroller);
        let enrolled = workload.clone();
        let sandbox_id = match tokio::task::spawn_blocking(move || enroller.ensure(&enrolled)).await
        {
            Ok(Ok(sandbox_id)) => sandbox_id,
            Ok(Err(error)) => return Err(tonic::Status::unavailable(error.to_string())),
            Err(_) => return Err(tonic::Status::unavailable("enrollment failed")),
        };

        let scheme = if http.scheme.is_empty() {
            "https".to_string()
        } else {
            http.scheme.clone()
        };
        let (host, port) = host_and_port(&http.host, &scheme);
        // The query string is dropped: Risk Guard never reads it.
        let path = http.path.split('?').next().unwrap_or("/").to_string();
        let raw = RawRequestInput {
            request_id: if http.id.is_empty() {
                uuid::Uuid::new_v4().to_string()
            } else {
                http.id.clone()
            },
            sandbox_id: sandbox_id.clone(),
            sandbox_name: sandbox_id,
            workspace: "spiffe".into(),
            scheme,
            host,
            port,
            method: http.method,
            path,
            binary_path: None,
            pid: None,
            ancestors: Vec::new(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
                }),
        };
        let normalized = match self.normalizer.normalize(&raw) {
            Ok(normalized) => normalized,
            // A request Risk Guard cannot make sense of is not forwarded.
            Err(error) => {
                return Ok(deny(&format!(
                    "the request could not be normalized: {error}"
                )));
            }
        };

        let store = Arc::clone(&self.store);
        let detector = Arc::clone(&self.detector);
        let gateway_id = self.enroller.gateway_id().to_string();
        let evaluated = tokio::time::timeout(
            EVALUATION_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                store.evaluate_native_authenticated(
                    &normalized,
                    detector.as_ref(),
                    &gateway_id,
                    true,
                    NativeObservationSource::VerifiedSupervisor,
                )
            }),
        )
        .await;
        match evaluated {
            Ok(Ok(Ok(evaluation))) if evaluation.outcome == DecisionOutcome::Deny => {
                Ok(deny(&evaluation.reason_code))
            }
            Ok(Ok(Ok(_))) => Ok(allow()),
            // Risk Guard could not decide: report an error, which the proxy treats as a failure to authorize (it fails closed).
            _ => Err(tonic::Status::unavailable("risk state unavailable")),
        }
    }
}

/// The `envoy.service.auth.v3.Authorization` gRPC service.
#[derive(Clone)]
pub struct AuthorizationServer {
    service: ExtAuthzService,
}

impl tonic::server::NamedService for AuthorizationServer {
    const NAME: &'static str = "envoy.service.auth.v3.Authorization";
}

struct CheckSvc(ExtAuthzService);

impl tonic::server::UnaryService<CheckRequest> for CheckSvc {
    type Response = CheckResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<CheckRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.check(request).await.map(tonic::Response::new) })
    }
}

impl<B> tonic::codegen::Service<http::Request<B>> for AuthorizationServer
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        if req.uri().path() == "/envoy.service.auth.v3.Authorization/Check" {
            let service = self.service.clone();
            return Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Ok(grpc.unary(CheckSvc(service), req).await)
            });
        }
        Box::pin(async move {
            let mut response = http::Response::new(tonic::body::Body::default());
            let headers = response.headers_mut();
            headers.insert(
                tonic::Status::GRPC_STATUS,
                (tonic::Code::Unimplemented as i32).into(),
            );
            headers.insert(
                http::header::CONTENT_TYPE,
                tonic::metadata::GRPC_CONTENT_TYPE,
            );
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_port_comes_from_the_host_or_the_scheme() {
        assert_eq!(
            host_and_port("api.example.com", "https"),
            ("api.example.com".into(), 443)
        );
        assert_eq!(
            host_and_port("api.example.com", "http"),
            ("api.example.com".into(), 80)
        );
        assert_eq!(
            host_and_port("api.example.com:8443", "https"),
            ("api.example.com".into(), 8443)
        );
        assert_eq!(host_and_port("api.example.com:notaport", "https").1, 443);
    }
}
