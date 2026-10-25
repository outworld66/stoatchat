//! Create a new MFA ticket or validate an existing one.
//! PUT /mfa/ticket
use revolt_config::config;
use revolt_database::{Account, Database, MFATicket, UnvalidatedTicket};
use revolt_models::v0;
use revolt_result::{Result, create_error};
use rocket::State;
use rocket::serde::json::Json;

/// # Create MFA ticket
///
/// Create a new MFA ticket or validate an existing one.
#[openapi(tag = "MFA")]
#[put("/ticket", data = "<data>")]
pub async fn create_ticket(
    db: &State<Database>,
    account: Option<Account>,
    existing_ticket: Option<UnvalidatedTicket>,
    data: Json<v0::MFAResponse>,
) -> Result<Json<v0::MFATicket>> {
    let session_authenticated = account.is_some();

    // Find the relevant account
    let mut account = match (account, existing_ticket) {
        (Some(_), Some(_)) => return Err(create_error!(OperationFailed)),
        (Some(account), _) => account,
        (_, Some(ticket)) => {
            db.delete_ticket(&ticket.id).await?;
            db.fetch_account(&ticket.account_id).await?
        }
        _ => return Err(create_error!(InvalidToken)),
    };

    // In OIDC-only mode the authenticated session is the reauthentication
    // proof; keep TOTP/recovery checks when the account has TOTP enabled.
    let settings = config().await;
    if !settings.api.oidc.is_enabled() || account.mfa.is_active() || !session_authenticated {
        account
            .consume_mfa_response(db, data.into_inner(), None)
            .await?;
    }

    // Create a new ticket for this account
    let ticket = MFATicket::new(account.id, true);
    ticket.save(db).await?;
    Ok(Json(ticket.into()))
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::Totp;
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{Header, Status};

    #[rocket::async_test]
    async fn success() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let res = harness
            .client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::MFATicket>().await.unwrap().validated);
    }

    #[rocket::async_test]
    async fn success_totp() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "totp_code": Totp::Enabled {
                        secret: "secret".to_string(),
                    }.generate_code().unwrap()
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::MFATicket>().await.is_some());
    }

    #[rocket::async_test]
    async fn failure_totp() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "totp_code": "000000"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidToken,
        ));
    }

    #[rocket::async_test]
    async fn failure_no_totp() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "this is the wrong mfa method"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::DisallowedMFAMethod,
        ));
    }
}
