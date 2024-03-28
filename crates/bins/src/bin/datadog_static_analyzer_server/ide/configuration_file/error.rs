use rocket::{http::ContentType, response::Responder, Response};
use serde_json::json;
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
    Decoder { source: anyhow::Error },
}

impl From<anyhow::Error> for ConfigFileError {
    fn from(value: anyhow::Error) -> Self {
        match value.downcast::<serde_yaml::Error>() {
            Ok(e) => Self::Parser { source: e },
            Err(e) => Self::Decoder { source: e },
        }
    }
}

impl<'r> Responder<'r, 'static> for ConfigFileError {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        let json = json!({"error": self.to_string(), "code": self.code()});
        Response::build_from(json.respond_to(request)?)
            .header(ContentType::JSON)
            .ok()
    }
}

impl ConfigFileError {
    pub fn code(&self) -> u16 {
        match self {
            Self::Parser { .. } => 1,
            Self::Decoder { .. } => 2,
        }
    }
}
