use std::sync::OnceLock;

pub mod authority;
pub mod buffer;
pub mod cache;
pub mod client;
pub mod context;
pub mod netutil;
pub mod protocol;
pub mod resolve;
pub mod server;

pub static PERFER_V6: OnceLock<bool> = OnceLock::new();
pub static DISABLE_V6: OnceLock<bool> = OnceLock::new();
