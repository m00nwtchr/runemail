use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {}

runesys::define_config!(Config);
