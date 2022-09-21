use anyhow::{anyhow, Result};
use std::path::Path;
use tokio::sync::mpsc::Sender;
use wasmtime_provider::wasmtime;

use crate::callback_requests::CallbackRequest;
use crate::policy_evaluator::{PolicyEvaluator, PolicyExecutionMode};
use crate::policy_evaluator_pre::PolicyEvaluatorPre;

/// Helper Struct that creates a `PolicyEvaluator` object
#[derive(Default)]
pub struct PolicyEvaluatorBuilder {
    engine: Option<wasmtime::Engine>,
    policy_id: String,
    policy_file: Option<String>,
    policy_contents: Option<Vec<u8>>,
    policy_module: Option<wasmtime::Module>,
    execution_mode: Option<PolicyExecutionMode>,
    settings: Option<serde_json::Map<String, serde_json::Value>>,
    callback_channel: Option<Sender<CallbackRequest>>,
    wasmtime_cache: bool,
}

impl PolicyEvaluatorBuilder {
    /// Create a new PolicyEvaluatorBuilder object. The `policy_id` must be
    /// specified.
    pub fn new(policy_id: String) -> PolicyEvaluatorBuilder {
        PolicyEvaluatorBuilder {
            policy_id,
            ..Default::default()
        }
    }

    /// [`wasmtime::Engine`] instance to be used when creating the
    /// policy evaluator
    ///
    /// **Warning:** when used, all the [`wasmtime::Engine`] specific settings
    /// must be set by the caller when creating the engine.
    /// This includes options like: cache, epoch counter
    pub fn engine(mut self, engine: wasmtime::Engine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Build the policy by reading the Wasm file from disk.
    /// Cannot be used at the same time as `policy_contents`
    pub fn policy_file(mut self, path: &Path) -> Result<PolicyEvaluatorBuilder> {
        let filename = path
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Cannot convert given path to String"))?;
        self.policy_file = Some(filename);
        Ok(self)
    }

    /// Build the policy by using the Wasm object given via the `data` array.
    /// Cannot be used at the same time as `policy_file`
    pub fn policy_contents(mut self, data: &[u8]) -> PolicyEvaluatorBuilder {
        self.policy_contents = Some(data.to_owned());
        self
    }

    /// Use a pre-built [`wasmtime::Module`] instance.
    /// **Warning:** you must provide also the [`wasmtime::Engine`] used
    /// to allocate the `Module`, otherwise the code will panic at runtime
    pub fn policy_module(mut self, module: wasmtime::Module) -> Self {
        self.policy_module = Some(module);
        self
    }

    /// Sets the policy execution mode
    pub fn execution_mode(mut self, mode: PolicyExecutionMode) -> PolicyEvaluatorBuilder {
        self.execution_mode = Some(mode);
        self
    }

    /// Enable Wasmtime cache feature
    pub fn enable_wasmtime_cache(mut self) -> PolicyEvaluatorBuilder {
        self.wasmtime_cache = true;
        self
    }

    /// Set the settings the policy will use at evaluation time
    pub fn settings(
        mut self,
        s: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> PolicyEvaluatorBuilder {
        self.settings = s;
        self
    }

    /// Specify the channel that is used by the synchronous world (the waPC `host_callback`
    /// function) to obtain information that can be computed only from within a
    /// tokio runtime.
    ///
    /// Note well: if no channel is given, the policy will still be created, but
    /// some waPC functions exposed by the host will not be available at runtime.
    /// The policy evaluation will not fail because of that, but the guest will
    /// get an error instead of the expected result.
    pub fn callback_channel(mut self, channel: Sender<CallbackRequest>) -> PolicyEvaluatorBuilder {
        self.callback_channel = Some(channel);
        self
    }

    /// Create the instance of `PolicyEvaluator` to be used
    pub fn build(&self) -> Result<PolicyEvaluator> {
        let pre = self.build_pre()?;
        pre.build(self.settings.clone(), self.callback_channel.clone())
    }

    pub fn build_pre(&self) -> Result<PolicyEvaluatorPre> {
        if self.policy_file.is_some() && self.policy_contents.is_some() {
            return Err(anyhow!(
                "Cannot specify 'policy_file' and 'policy_contents' at the same time"
            ));
        }
        if self.policy_file.is_some() && self.policy_module.is_some() {
            return Err(anyhow!(
                "Cannot specify 'policy_file' and 'policy_module' at the same time"
            ));
        }
        if self.policy_contents.is_some() && self.policy_module.is_some() {
            return Err(anyhow!(
                "Cannot specify 'policy_contents' and 'policy_module' at the same time"
            ));
        }

        if self.policy_file.is_none()
            && self.policy_contents.is_none()
            && self.policy_module.is_none()
        {
            return Err(anyhow!(
                "Must specify one among: `policy_file`, `policy_contents` and `policy_module`"
            ));
        }

        if self.engine.is_none() && self.policy_module.is_some() {
            return Err(anyhow!(
                "You must provide the `engine` that was used to instantiate the given `policy_module`"
            ));
        }

        let mode = self
            .execution_mode
            .ok_or_else(|| anyhow!("Must specify execution mode"))?;

        let engine = self
            .engine
            .as_ref()
            .map_or_else(
                || {
                    let mut wasmtime_config = wasmtime::Config::new();
                    if self.wasmtime_cache {
                        wasmtime_config.cache_config_load_default()?;
                    }

                    wasmtime::Engine::new(&wasmtime_config)
                },
                |e| Ok(e.clone()),
            )
            .map_err(|e| anyhow!("cannot create wasmtime engine: {:?}", e))?;

        let module: wasmtime::Module = if let Some(m) = &self.policy_module {
            // it's fine to clone a Module, this is a cheap operation that just
            // copies its internal reference. See wasmtime docs
            m.clone()
        } else {
            match &self.policy_file {
                Some(file) => wasmtime::Module::from_file(&engine, file),
                None => wasmtime::Module::new(&engine, self.policy_contents.as_ref().unwrap()),
            }?
        };

        PolicyEvaluatorPre::new(engine, module, &self.policy_id, mode)
    }
}
