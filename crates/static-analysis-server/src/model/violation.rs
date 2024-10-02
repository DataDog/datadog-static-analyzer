use kernel::model::violation::Violation;
use serde::{Deserialize, Serialize};

/// A newtype [`Violation`] that provides a custom serialization for the server.
#[derive(Deserialize, Debug, Serialize, Clone)]
#[serde(transparent)]
pub struct ServerViolation(pub Violation);

impl From<Violation> for ServerViolation {
    fn from(value: Violation) -> Self {
        Self(value)
    }
}

impl<'a> From<&'a Violation> for ServerViolation {
    fn from(value: &'a Violation) -> Self {
        Self(value.clone())
    }
}
