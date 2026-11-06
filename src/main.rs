use std::sync::Arc;
use axum::{Router, extract::{Path, State}, http::{HeaderMap}, response::{IntoResponse, Redirect}, routing::get};
use reqwest::header::SET_COOKIE;
use serde::Deserialize;

pub mod google;
pub mod github;
pub mod oauth;
pub mod common;


#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthRequest {
    pub code: String,
    pub state: String,
    pub iss: String,
}




struct AppState {
    oauth_master: oauth::OAuthMaster
}

async fn redirect_to_provider(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse, &'static str> {
    let p_type = common::OAuthProviderType::from(&provider)
        .ok_or("invalid provider")?;
    let provider = state.oauth_master
        .get(p_type)
        .ok_or("provider is not supported yet")?;

    let (url, cookie) = provider.auth_url();
    let mut headers = HeaderMap::new();
    headers
        .insert(
            SET_COOKIE, 
            cookie 
            .parse()
            .map_err(|_| "could not set the cookie")?
        );

    Ok((
            headers, 
            Redirect::to(url.as_ref())
    ))
}


#[axum::debug_handler]
async fn callback(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(payload): axum::extract::Query<AuthRequest>,
    Path(provider): Path<String>,
) -> Result<axum::Json<common::ExternalUser>, &'static str>{
    let p_type = common::OAuthProviderType::from(&provider)
        .ok_or("invalid provider")?;
    let provider = state.oauth_master
        .get(p_type)
        .ok_or("provider is not supported yet")?;
    let user = provider.get_user(payload.code)
        .await
        .map_err(|_| "provider did not give us the user")?;
    // Let's be smart and return JWT tokens ;)
    Ok(axum::Json(user))
}



#[tokio::main]
async fn main() {
    // We're doing google here
    dotenvy::dotenv().ok();
    let client_id = std::env::var("OAUTH_CLIENT_ID_GOOGLE").unwrap();
    let client_secret = std::env::var("OAUTH_CLIENT_SECRET_GOOGLE").unwrap();
    let token_url = "https://oauth2.googleapis.com/token".to_string();
    let auth_url = "https://accounts.google.com/o/oauth2/v2/auth".to_string();
    let redirect = "http://localhost:8000/api/auth/v1/oauth/google/callback".to_string();
    let user_url = "https://openidconnect.googleapis.com/v1/userinfo".to_string();

    let mut master = oauth::OAuthMaster::new();
    let google_oauth = oauth::OAuthProvider::init(
        common::OAuthProviderType::Google, 
        client_id, 
        client_secret, 
        redirect, 
        auth_url, 
        token_url, 
        user_url, 
        vec!["openid".to_string(), "email".to_string(), "profile".to_string()]);
    master.add(google_oauth);
    let state = AppState{oauth_master: master};
    let shared = Arc::new(state);
    let app = Router::new()
        .route("/{provider}/login", get(redirect_to_provider))
        .route("/api/auth/v1/oauth/{provider}/callback", get(callback))
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.expect("server failed");

}
