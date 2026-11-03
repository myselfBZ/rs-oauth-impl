use reqwest::header::USER_AGENT;
use serde::{Deserialize, Serialize};

use crate::common::{self, AuthError, ExternalUser};


#[derive(Debug, Clone, Deserialize, Serialize)]
struct GithubUserInfo {
    id: i64,
    name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct EmailInfo {
    email: String,
    verified: bool,
    primary: bool
}

pub async fn fetch_user(
    token: String, 
    user_url: String,
    client: &reqwest::Client
    ) -> Result<common::ExternalUser, common::AuthError> {
    let user: GithubUserInfo = client
        .get(user_url)
        .bearer_auth(token.clone())
        .header(USER_AGENT, "uPortal v0.1.0")
        .send()
        .await
        .map_err(|e| AuthError::Unknown(e.to_string()))?
        .error_for_status()
        .map_err(|e| AuthError::Unknown(e.to_string()))?
        .json()
        .await
        .map_err(|e| AuthError::Unknown(e.to_string()))?;

    let emails: Vec<EmailInfo> = client
        .get("https://api.github.com/user/emails")
        .bearer_auth(token)
        .header(USER_AGENT, "uPortal v0.1.0")
        .send()
        .await
        .map_err(|e| AuthError::TokenExchange(e.to_string()))?
        .error_for_status()
        .map_err(|e| AuthError::TokenExchange(e.to_string()))?
        .json()
        .await
        .map_err(|e| AuthError::Unknown(e.to_string()))?;

    let primary = emails.iter().find(|e| e.primary && e.verified).ok_or(AuthError::MissingEmail)?.clone();

    Ok(ExternalUser{
        email: primary.email,
        full_name: user.name,
        provider: common::OAuthProviderType::Github,
        id: user.id.to_string(),
    })
}
