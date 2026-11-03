use reqwest::header::USER_AGENT;
use serde::Deserialize;
use crate::common::{self, ExternalUser, OAuthProviderType::Google};

#[derive(Debug, Deserialize)]
pub struct GoogleUserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub locale: Option<String>,
}


pub async fn fetch_user(
    token: String, 
    user_url: String,
    client: &reqwest::Client
    ) -> Result<ExternalUser, crate::common::AuthError> {
    let user: GoogleUserInfo = client
        .get(user_url)
        .bearer_auth(token.clone())
        .header(USER_AGENT, "uPortal v0.1.0")
        .send()
        .await
        .map_err(|e| crate::common::AuthError::Unknown(e.to_string()))?
        .error_for_status()
        .map_err(|e| crate::common::AuthError::Unknown(e.to_string()))?
        .json()
        .await
        .map_err(|e| crate::common::AuthError::Unknown(e.to_string()))?;

    let display_name = user.name.or_else(|| match (user.given_name, user.family_name) {
        (Some(g), Some(f)) => Some(format!("{g} {f}")),
        (g, f) => g.or(f),
    }).ok_or(common::AuthError::MissingFullName)?;

    let email = user.email.ok_or(common::AuthError::MissingEmail)?;
    let verified = user.email_verified.ok_or(common::AuthError::MissingEmail)?;
    if !verified {
        return Err(common::AuthError::MissingEmail);
    }

    return Ok(ExternalUser {
        id: user.sub,
        full_name: display_name,
        provider: Google,
        email: email
    })
}
