use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest,
};
use redis_kiss::{AsyncCommands, get_connection};
use revolt_config::{Settings, config};
use revolt_database::{Database, EmailVerification, MFATicket, util::email::normalise_email};
use revolt_models::v0;
use revolt_result::{Result, create_error};
use rocket::{State, response::Redirect, serde::json::Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct LoginFlow {
    verifier: String,
    nonce: String,
}

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

fn redirect_uri(settings: &Settings) -> String {
    format!(
        "{}/auth/session/oidc/callback",
        settings.hosts.api.trim_end_matches('/')
    )
}

async fn client(settings: &Settings) -> Result<(OidcClient, reqwest::Client)> {
    let cfg = &settings.api.oidc;
    if cfg.issuer.is_empty() || cfg.client_id.is_empty() || cfg.client_secret.is_empty() {
        return Err(create_error!(OperationFailed));
    }

    let http = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| create_error!(OperationFailed))?;
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(cfg.issuer.clone()).map_err(|_| create_error!(OperationFailed))?,
        &http,
    )
    .await
    .map_err(|_| create_error!(OperationFailed))?;

    Ok((
        CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(cfg.client_id.clone()),
            Some(ClientSecret::new(cfg.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri(settings)).map_err(|_| create_error!(OperationFailed))?,
        ),
        http,
    ))
}

/// Start an OIDC authorization-code flow with PKCE.
#[get("/oidc")]
pub async fn start() -> Result<Redirect> {
    let settings = config().await;
    let (client, _) = client(&settings).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(challenge)
        .url();

    let mut redis = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();
    let flow = serde_json::to_string(&LoginFlow {
        verifier: verifier.secret().clone(),
        nonce: nonce.secret().clone(),
    })
    .map_err(|_| create_error!(InternalError))?;
    let _: () = redis
        .set_ex(format!("oidc:state:{}", state.secret()), flow, 300)
        .await
        .map_err(|_| create_error!(InternalError))?;
    Ok(Redirect::to(url.to_string()))
}

/// Complete OIDC login and send the browser back with a short-lived one-time ticket.
#[get("/oidc/callback?<code>&<state>&<error>")]
pub async fn callback(
    db: &State<Database>,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
) -> Result<Redirect> {
    let settings = config().await;
    let app = format!("{}/login/oidc", settings.hosts.app.trim_end_matches('/'));
    let fail = || Redirect::to(format!("{app}#error=oidc"));
    if error.is_some() {
        return Ok(fail());
    }

    let state = state.ok_or_else(|| create_error!(InvalidCredentials))?;
    let Some(code) = code else { return Ok(fail()) };
    let mut redis = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();
    let flow: Option<String> = redis
        .get_del(format!("oidc:state:{state}"))
        .await
        .map_err(|_| create_error!(InternalError))?;
    let Some(flow) = flow.and_then(|json| serde_json::from_str::<LoginFlow>(&json).ok()) else {
        return Ok(fail());
    };
    drop(redis);
    let (client, http) = client(&settings).await?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| create_error!(InvalidCredentials))?
        .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier))
        .request_async(&http)
        .await
        .map_err(|_| create_error!(InvalidCredentials))?;
    let id_token = token
        .id_token()
        .ok_or_else(|| create_error!(InvalidCredentials))?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(flow.nonce))
        .map_err(|_| create_error!(InvalidCredentials))?;
    if !claims.email_verified().unwrap_or(false) {
        return Ok(fail());
    }

    let email = claims
        .email()
        .ok_or_else(|| create_error!(InvalidCredentials))?;
    let email = normalise_email(email.as_str().to_owned());
    let account = db
        .fetch_account_by_normalised_email(&email)
        .await?
        .filter(|account| matches!(account.verification, EmailVerification::Verified))
        .ok_or_else(|| create_error!(InvalidCredentials))?;
    let response = if account.disabled {
        v0::ResponseLogin::Disabled {
            user_id: account.id,
        }
    } else if account.mfa.is_active() {
        let mut ticket = MFATicket::new(account.id, false);
        ticket.populate(&account.mfa).await;
        ticket.save(db).await?;
        v0::ResponseLogin::MFA {
            ticket: ticket.token,
            allowed_methods: account
                .mfa
                .get_methods()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    } else {
        v0::ResponseLogin::Success(
            account
                .create_session(db, "Stoat for Web (OIDC)".into())
                .await?
                .into(),
        )
    };

    let ticket = nanoid::nanoid!(32);
    let response = serde_json::to_string(&response).map_err(|_| create_error!(InternalError))?;
    let mut redis = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();
    let _: () = redis
        .set_ex(format!("oidc:ticket:{ticket}"), response, 90)
        .await
        .map_err(|_| create_error!(InternalError))?;
    Ok(Redirect::to(format!("{app}#ticket={ticket}")))
}

/// Exchange a one-time browser ticket for the usual Stoat login response.
#[post("/oidc/<ticket>")]
pub async fn exchange(ticket: &str) -> Result<Json<v0::ResponseLogin>> {
    let mut redis = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();
    let response: Option<String> = redis
        .get_del(format!("oidc:ticket:{ticket}"))
        .await
        .map_err(|_| create_error!(InternalError))?;
    let Some(response) = response else {
        return Err(create_error!(InvalidCredentials));
    };
    serde_json::from_str(&response)
        .map(Json)
        .map_err(|_| create_error!(InternalError))
}

pub fn routes() -> Vec<rocket::Route> {
    routes![start, callback, exchange]
}
