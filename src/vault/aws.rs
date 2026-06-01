use std::{collections::HashMap, sync::Arc};

use super::VaultError;

pub fn register(m: &mut HashMap<&'static str, super::BuildFn>) {
    m.insert("awskms", build);
}

fn build(_name: &str, _table: &toml::Value) -> Result<Arc<dyn super::SigningVault>, anyhow::Error> {
    Err(VaultError::not_implemented("awskms").into())
}
