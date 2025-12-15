#[cfg(feature = "rustcrypto")]
pub mod bedrock;

#[cfg(feature = "openssl")]
#[path = "bedrock_openssl.rs"]
pub mod bedrock;

pub use bedrock::*;