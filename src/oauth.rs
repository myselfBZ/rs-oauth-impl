
use std::collections::HashMap;
use crate::{common::{AuthError, ExternalUser, OAuthProviderType}, github, google};
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, RedirectUrl, Scope, TokenResponse, TokenUrl};

type BasicClient = oauth2::basic::BasicClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet
>;

#[derive(Debug, Clone)]
pub struct OAuthProvider {
    p_type: OAuthProviderType,
    user_url: String,
    scopes: Vec<String>,
    client: BasicClient
}

impl OAuthProvider {

    pub fn init(
        p_type: OAuthProviderType,
        client_id: String,
        client_secret: String,
        redirect_url: String,
        auth_url: String,
        token_url: String,
        user_url: String,
        scopes: Vec<String>
    ) -> Self {
        let client = oauth2::basic::BasicClient::new(ClientId::new(client_id))
            .set_client_secret(ClientSecret::new(client_secret))
            // FIXME: remove the damn unwrap
            .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
            .set_auth_uri(AuthUrl::new(auth_url).unwrap())
            .set_token_uri(TokenUrl::new(token_url).unwrap());
        OAuthProvider { client, p_type, user_url, scopes }
    }

    pub fn auth_url(&self) -> (String, String) {
        let mut req = self.client.authorize_url(CsrfToken::new_random);
        for scope in self.scopes.clone() {
            req = req.add_scope(Scope::new(scope.clone()));
        }
        let(auth_url, csrf_token) = req.url();
        let csrf_token = csrf_token.into_secret();
        let cookie = format!("csrf_token={csrf_token}; SameSite=Lax; HttpOnly; Secure; Path=/");
        return (auth_url.to_string(), cookie)
    }

    pub async fn get_user(&self, code: String) -> Result<ExternalUser, AuthError> {
        let client = reqwest::Client::new();
        let token = self
                     .client
                     .exchange_code(AuthorizationCode::new(code))
                     .request_async(&client)
                     .await
                     .map_err(|e| { 
                         let mut err_msg = format!("ERROR: {}", e.to_string());
                         let mut cur_fail: Option<&dyn std::error::Error> = Some(&e);
                         while let Some(cause) = cur_fail {
                             err_msg += &format!("\n    caused by: {}", cause);
                             cur_fail = cause.source();
                         }
                         println!("{}", err_msg);
                         AuthError::TokenExchange(e.to_string())
                     })?;

        match self.p_type {
            OAuthProviderType::Github => github::fetch_user(
                    token.access_token().secret().to_string(), 
                    self.user_url.clone(), 
                    &client
                )
                .await,
            _ => google::fetch_user(
                    token.access_token().secret().to_string(), 
                    self.user_url.clone(), 
                    &client
                )
                .await
        }
    }

}

#[derive(Clone, Debug)]
pub struct OAuthMaster {
    providers: HashMap<OAuthProviderType, OAuthProvider>
}

impl OAuthMaster {

    pub fn new() -> Self {
        let providers = HashMap::new();
        Self { providers }
    }

    pub fn add(&mut self, provider: OAuthProvider) {
        self.providers.insert(provider.p_type, provider);
    }

    pub fn get(&self, provider_type: OAuthProviderType) -> Option<&OAuthProvider> {
        self.providers.get(&provider_type)
    }

    pub fn remove(&mut self, provider_type: OAuthProviderType) {
        self.providers.remove(&provider_type);
    }

}
