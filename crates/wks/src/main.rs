#![warn(clippy::pedantic)]

use std::{ops::Deref, path::PathBuf, sync::Arc};

use axum::{
	Router,
	extract::{Path, Request, State},
	http::StatusCode,
	response::IntoResponse,
	routing::get,
};
use axum_extra::extract::Host;
use proto::wks::web_key_service_server::{WebKeyService as WKS, WebKeyServiceServer};
use runemail_proto as proto;
use runesys::Service;
use sequoia_openpgp::serialize::MarshalInto;

use crate::provider::{FileKeyProvider, KeyProvider, KeyProviderType};

mod config;
mod provider;

pub struct WKSInner {
	pub provider: KeyProviderType,
}

#[derive(Service, Clone)]
#[server(WebKeyServiceServer)]
pub struct WebKeyService(Arc<WKSInner>);

impl Deref for WebKeyService {
	type Target = WKSInner;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl WKS for WebKeyService {}

async fn get_key(
	State(wks): State<WebKeyService>,
	Path(local): Path<String>,
	Host(host): Host,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	if let Some(key) = wks.provider.discover(local, host) {
		Ok(key.to_vec().unwrap().into_response())
	} else {
		Err((StatusCode::NOT_FOUND, "Not found".to_string()))
	}
}

async fn get_policy() -> String {
	String::new()
}

fn app(wks: WebKeyService) -> Router {
	Router::new()
		.route("/.well-known/openpgpkeys/hu/{local}", get(get_key))
		.route("/.well-known/openpgpkeys/policy", get(get_policy))
		.with_state(wks)
}

#[tokio::main]
async fn main() -> Result<(), runesys::error::Error> {
	let wks = WebKeyService(Arc::new(WKSInner {
		provider: FileKeyProvider::new(PathBuf::from("keys")).into(),
	}));
	let app = app(wks.clone());

	wks.builder().with_http(app).run().await
}
