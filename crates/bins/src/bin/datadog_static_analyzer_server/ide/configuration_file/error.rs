use thiserror::Error;

#[derive(Debug, Error)]
#[error("Static Analysis Config file error")]
pub enum ConfigFileError {
    #[error("Error parsing yaml file")]
    Parser {
        #[from]
        source: serde_yaml::Error,
    },
    #[error("Error decoding base64 string")]
    Decoder {
        #[from]
        source: anyhow::Error,
    },
}
