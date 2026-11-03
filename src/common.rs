
pub const GOOGLE: &str = "google";
pub const GITHUB: &str = "github";

use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("missing a full name")]
    MissingFullName,

    #[error("missing a verified email")]
    MissingEmail,

    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    #[error("somebody fucked up: {0}")]
    Unknown(String)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
pub enum OAuthProviderType {
    Google,
    Github
}

impl OAuthProviderType {
    pub fn from(name: &str) -> Option<Self> {
        match name {
            GOOGLE => Some(Self::Google),
            GITHUB => Some(Self::Github),
            _ => None
        }
    }

    pub fn to_string(self) -> String {
        match self {
            Self::Google => "google".to_string(),
            Self::Github => "github".to_string(),
        }
    }
}


#[derive(Serialize, JsonSchema)]
pub struct ExternalUser {
    pub id: String,
    pub full_name: String,
    pub email: String,
    pub provider: OAuthProviderType,
}
