use std::convert::TryInto;

use anyhow::{anyhow, Result};
use wapc::WapcHost;
use wasmtime_provider::wasmtime;

use tokio::sync::mpsc;

use crate::callback_requests::CallbackRequest;
use crate::policy::Policy;
use crate::policy_evaluator::{
    BurregoEvaluator, PolicyEvaluator, PolicyExecutionMode, RegoPolicyExecutionMode, Runtime,
};
use crate::runtimes::{wapc::host_callback as wapc_callback, wapc::WAPC_POLICY_MAPPING};

/// This is struct allows fast creation of a [`crate::policy_evaluator::Runtime`]
/// instances that can evaluate Rego code.
#[derive(Clone)]
struct BurregoEvaluatorPre {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    entrypoint_id: i32,
    execution_mode: RegoPolicyExecutionMode,
}

impl BurregoEvaluatorPre {
    /// Create a Burrego runtime as fast as possible
    fn build(self) -> Result<crate::policy_evaluator::Runtime> {
        let evaluator = burrego::Evaluator::from_engine_and_module(
            self.engine.clone(),
            self.module.clone(),
            crate::runtimes::burrego::new_host_callbacks(),
        )?;

        Ok(Runtime::Burrego(Box::new(BurregoEvaluator {
            evaluator,
            entrypoint_id: self.entrypoint_id,
            policy_execution_mode: self.execution_mode,
        })))
    }
}

/// This struct allows fast creation of [`PolicyEvaluator`] instance.
///
/// On top of reducing the creation time, it also reduces memory consumption.
#[derive(Clone)]
pub struct PolicyEvaluatorPre {
    policy_id: String,
    execution_mode: PolicyExecutionMode,
    wasmtime_engine_provider: Option<wasmtime_provider::WasmtimeEngineProvider>,
    burrego_evaluator_pre: Option<BurregoEvaluatorPre>,
}

impl PolicyEvaluatorPre {
    /// Create a new instance starting from pre-allocated resources.
    /// Not to be used directly, rely on `PolicyEvaluatorBuilder` instead
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        policy_id: &str,
        execution_mode: PolicyExecutionMode,
    ) -> Result<Self> {
        let policy_id = policy_id.to_string();

        match execution_mode {
            PolicyExecutionMode::KubewardenWapc => {
                let wasmtime_engine_provider = Some(
                    wasmtime_provider::WasmtimeEngineProviderBuilder::new()
                        .engine(engine)
                        .module(module)
                        .build()?,
                );
                Ok(Self {
                    execution_mode,
                    policy_id,
                    wasmtime_engine_provider,
                    burrego_evaluator_pre: None,
                })
            }
            PolicyExecutionMode::Opa | PolicyExecutionMode::OpaGatekeeper => {
                let burrego_evaluator_pre = Some(BurregoEvaluatorPre {
                    engine,
                    module,
                    entrypoint_id: 0, // currently hard-coded to this value
                    execution_mode: execution_mode.try_into()?,
                });

                Ok(Self {
                    execution_mode,
                    policy_id,
                    burrego_evaluator_pre,
                    wasmtime_engine_provider: None,
                })
            }
        }
    }

    /// Create a `PolicyEvaluator` as fast as possible, saving memory usage too
    pub fn build(
        self,
        settings: Option<serde_json::Map<String, serde_json::Value>>,
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
    ) -> Result<PolicyEvaluator> {
        let (policy, runtime) = match self.execution_mode {
            PolicyExecutionMode::KubewardenWapc => {
                let engine_provider = self
                    .wasmtime_engine_provider
                    .ok_or_else(|| {
                        anyhow!(
                        "Cannot instantiate a waPC PolicyEvaluator, the engine provider is None"
                    )
                    })?
                    .clone();

                let wapc_host =
                    WapcHost::new(Box::new(engine_provider), Some(Box::new(wapc_callback)))?;
                let policy = Self::from_contents_internal(
                    self.policy_id,
                    callback_channel,
                    || Some(wapc_host.id()),
                    Policy::new,
                    self.execution_mode,
                )?;

                let policy_runtime = Runtime::Wapc(wapc_host);
                (policy, policy_runtime)
            }
            PolicyExecutionMode::Opa | PolicyExecutionMode::OpaGatekeeper => {
                let policy = Self::from_contents_internal(
                    self.policy_id,
                    callback_channel,
                    || None,
                    Policy::new,
                    self.execution_mode,
                )?;
                let policy_runtime = self
                    .burrego_evaluator_pre
                    .ok_or_else(|| {
                        anyhow!("Cannot instantiate a Rego PolicyEvaluator, the BurregoEvaluatorPre is None")
                    })?
                    .build()?;
                (policy, policy_runtime)
            }
        };

        Ok(PolicyEvaluator {
            runtime,
            policy,
            settings: settings.unwrap_or_default(),
        })
    }

    fn from_contents_internal<E, P>(
        id: String,
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
        engine_initializer: E,
        policy_initializer: P,
        policy_execution_mode: PolicyExecutionMode,
    ) -> Result<Policy>
    where
        E: Fn() -> Option<u64>,
        P: Fn(String, Option<u64>, Option<mpsc::Sender<CallbackRequest>>) -> Result<Policy>,
    {
        let instance_id = engine_initializer();
        let policy = policy_initializer(id, instance_id, callback_channel)?;
        if policy_execution_mode == PolicyExecutionMode::KubewardenWapc {
            WAPC_POLICY_MAPPING
                .write()
                .expect("cannot write to global WAPC_POLICY_MAPPING")
                .insert(
                    instance_id.ok_or_else(|| anyhow!("invalid policy id"))?,
                    policy.clone(),
                );
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_registered_in_the_mapping() -> Result<()> {
        let policy_name = "policy_is_registered_in_the_mapping";

        // We cannot set policy.id at build time, because some attributes
        // of Policy are private.
        let mut policy = Policy::default();
        policy.id = policy_name.to_string();

        let policy_id = 1;

        PolicyEvaluatorPre::from_contents_internal(
            "mock_policy".to_string(),
            None,
            || Some(policy_id),
            |_, _, _| Ok(policy.clone()),
            PolicyExecutionMode::KubewardenWapc,
        )?;

        let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
        let found = policy_mapping
            .iter()
            .find(|(_id, policy)| policy.id == policy_name);

        assert!(found.is_some());

        Ok(())
    }

    #[test]
    fn policy_is_not_registered_in_the_mapping_if_not_wapc() -> Result<()> {
        let policy_name = "policy_is_not_registered_in_the_mapping_if_not_wapc";

        // We cannot set policy.id at build time, because some attributes
        // of Policy are private.
        let mut policy = Policy::default();
        policy.id = policy_name.to_string();

        let policy_id = 1;

        PolicyEvaluatorPre::from_contents_internal(
            policy_name.to_string(),
            None,
            || Some(policy_id),
            |_, _, _| Ok(policy.clone()),
            PolicyExecutionMode::OpaGatekeeper,
        )?;

        let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
        let found = policy_mapping
            .iter()
            .find(|(_id, policy)| policy.id == policy_name);

        assert!(found.is_none());
        Ok(())
    }
}
