use anyhow::{anyhow, Result};
use cached::proc_macro::cached;
use policy_fetcher::{registry::config::DockerConfig, sigstore, sources::Sources};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::callback_requests::{CallbackRequest, CallbackResponse};

use policy_fetcher::kubewarden_policy_sdk::host_capabilities::verification::KeylessInfo;
use policy_fetcher::kubewarden_policy_sdk::host_capabilities::CallbackRequestType;
use policy_fetcher::verify::FulcioAndRekorData;

mod oci;
mod sigstore_verification;

const DEFAULT_CHANNEL_BUFF_SIZE: usize = 100;

/// Helper struct that creates CallbackHandler objects
pub struct CallbackHandlerBuilder {
    oci_sources: Option<Sources>,
    docker_config: Option<DockerConfig>,
    channel_buffer_size: usize,
    shutdown_channel: Option<oneshot::Receiver<()>>,
}

impl Default for CallbackHandlerBuilder {
    fn default() -> Self {
        CallbackHandlerBuilder {
            oci_sources: None,
            docker_config: None,
            shutdown_channel: None,
            channel_buffer_size: DEFAULT_CHANNEL_BUFF_SIZE,
        }
    }
}

impl CallbackHandlerBuilder {
    #![allow(dead_code)]

    /// Provide all the information needed to access OCI registries. Optional
    pub fn registry_config(
        mut self,
        sources: Option<Sources>,
        docker_config: Option<DockerConfig>,
    ) -> Self {
        self.oci_sources = sources;
        self.docker_config = docker_config;
        self
    }

    /// Set the size of the channel used by the sync world to communicate with
    /// the CallbackHandler. Optional
    pub fn channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = size;
        self
    }

    /// Set the onetime channel used to stop the endless loop of
    /// CallbackHandler. Mandatory
    pub fn shutdown_channel(mut self, shutdown_channel: oneshot::Receiver<()>) -> Self {
        self.shutdown_channel = Some(shutdown_channel);
        self
    }

    /// Create a CallbackHandler object
    pub fn build(self) -> Result<CallbackHandler> {
        let (tx, rx) = mpsc::channel::<CallbackRequest>(self.channel_buffer_size);
        if self.shutdown_channel.is_none() {
            return Err(anyhow!("shutdown_channel_rx not provided"));
        }

        let oci_client = oci::Client::new(self.oci_sources.clone(), self.docker_config.clone());
        let repo = sigstore::tuf::SigstoreRepository::fetch(None)?;
        let fulcio_and_rekor_data = FulcioAndRekorData::FromTufRepository { repo };
        let sigstore_client = sigstore_verification::Client::new(
            self.oci_sources.clone(),
            self.docker_config.clone(),
            &fulcio_and_rekor_data,
        )?;

        Ok(CallbackHandler {
            oci_client,
            sigstore_client,
            tx,
            rx,
            shutdown_channel: self.shutdown_channel.unwrap(),
        })
    }
}

/// Struct that computes request coming from a Wasm guest.
/// This should be used only to handle the requests that need some async
/// code in order to be fulfilled.
pub struct CallbackHandler {
    oci_client: oci::Client,
    sigstore_client: sigstore_verification::Client,
    rx: mpsc::Receiver<CallbackRequest>,
    tx: mpsc::Sender<CallbackRequest>,
    shutdown_channel: oneshot::Receiver<()>,
}

impl CallbackHandler {
    /// Returns the sender side of the channel that can be used by the sync code
    /// (like the `host_callback` function of PolicyEvaluator)
    /// to request the computation of async code.
    ///
    /// Can be invoked as many times as wanted.
    pub fn sender_channel(&self) -> mpsc::Sender<CallbackRequest> {
        self.tx.clone()
    }

    /// Enter an endless loop that:
    ///    1. Waits for requests to be evaluated
    ///    2. Evaluate the request
    ///    3. Send back the result of the evaluation
    ///
    /// The loop is interrupted only when a message is sent over the
    /// `shutdown_channel`.
    pub async fn loop_eval(&mut self) {
        loop {
            tokio::select! {
                // place the shutdown check before the message evaluation,
                // as recommended by tokio's documentation about select!
                _ = &mut self.shutdown_channel => {
                    return;
                },
                maybe_req = self.rx.recv() => {
                    if let Some(req) = maybe_req {
                        match req.request {
                            CallbackRequestType::OciManifestDigest {
                                image,
                            } => {
                                let response = get_oci_digest_cached(&self.oci_client, &image)
                                    .await
                                    .map(|digest| {
                                        if digest.was_cached {
                                            debug!(?image, "Got image digest from cache");
                                        } else {
                                            debug!(?image, "Got image digest by querying remote registry");
                                        }
                                        CallbackResponse {
                                        payload: digest.as_bytes().to_vec(),
                                    }});

                                if let Err(e) = req.response_channel.send(response) {
                                    warn!("callback handler: cannot send response back: {:?}", e);
                                }
                            },
                            CallbackRequestType::SigstorePubKeyVerify {
                                image,
                                pub_keys,
                                annotations,
                            } => {
                                let response = get_sigstore_pub_key_verification_cached(&mut self.sigstore_client, image.clone(), pub_keys, annotations)
                                    .await
                                    .map(|is_trusted| {
                                        if is_trusted.was_cached {
                                            debug!(?image, "Got sigstore pub keys verification from cache");
                                        } else {
                                            debug!(?image, "Got sigstore pub keys verification by querying remote registry");
                                        }
                                    let is_trusted_byte: u8 = is_trusted.value.into();
                                        CallbackResponse {
                                        payload: vec!(is_trusted_byte)
                                    }});

                                if let Err(e) = req.response_channel.send(response) {
                                    warn!("callback handler: cannot send response back: {:?}", e);
                                }
                                },
                            CallbackRequestType::SigstoreKeylessVerify {
                                image,
                                keyless,
                                annotations,
                            } => {
                                let response = get_sigstore_keyless_verification_cached(&mut self.sigstore_client, image.clone(), keyless, annotations)
                                    .await
                                    .map(|is_trusted| {
                                        if is_trusted.was_cached {
                                            debug!(?image, "Got sigstore pub keys verification from cache");
                                        } else {
                                            debug!(?image, "Got sigstore pub keys verification by querying remote registry");
                                        }
                                    let is_trusted_byte: u8 = is_trusted.value.into();
                                        CallbackResponse {
                                        payload: vec!(is_trusted_byte)
                                    }});

                                if let Err(e) = req.response_channel.send(response) {
                                    warn!("callback handler: cannot send response back: {:?}", e);
                                }
                                },
                        }
                    }
                },
            }
        }
    }
}

// Interacting with a remote OCI registry is time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * only the image "url" is used as key. oci::Client is not hashable, plus
//     the client is always the same
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
#[cached(
    time = 60,
    result = true,
    sync_writes = true,
    key = "String",
    convert = r#"{ format!("{}", img) }"#,
    with_cached_flag = true
)]
async fn get_oci_digest_cached(
    oci_client: &oci::Client,
    img: &str,
) -> Result<cached::Return<String>> {
    oci_client.digest(img).await.map(cached::Return::new)
}

// Sigstore verifications are time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
#[cached(
    time = 60,
    result = true,
    sync_writes = true,
    key = "String",
    convert = r#"{ format!("{}{:?}{:?}", image, pub_keys, annotations)}"#,
    with_cached_flag = true
)]
async fn get_sigstore_pub_key_verification_cached(
    client: &mut sigstore_verification::Client,
    image: String,
    pub_keys: Vec<String>,
    annotations: Option<HashMap<String, String>>,
) -> Result<cached::Return<bool>> {
    client
        .is_pub_key_trusted(image, pub_keys, annotations)
        .await
        .map(cached::Return::new)
}

// Sigstore verifications are time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
#[cached(
    time = 60,
    result = true,
    sync_writes = true,
    key = "String",
    convert = r#"{ format!("{}{:?}{:?}", image, keyless, annotations)}"#,
    with_cached_flag = true
)]
async fn get_sigstore_keyless_verification_cached(
    client: &mut sigstore_verification::Client,
    image: String,
    keyless: Vec<KeylessInfo>,
    annotations: Option<HashMap<String, String>>,
) -> Result<cached::Return<bool>> {
    client
        .is_keyless_trusted(image, keyless, annotations)
        .await
        .map(cached::Return::new)
}
