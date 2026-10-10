# OpenID Connect login

The API and web client support OIDC Authorization Code login with PKCE. Configure the provider and client credentials in the API environment:

```toml
[api.oidc]
issuer = "https://identity.example.com"
client_id = "stoat"
client_secret = ""
```

Set the secret outside `Revolt.toml` as `REVOLT__API__OIDC__CLIENT_SECRET`. Register this exact callback URL with the provider:

```text
<hosts.api>/auth/session/oidc/callback
```

The client requests the `openid` and `email` scopes. Login requires a verified email claim and an existing Stoat account with the same verified email. New accounts are not created by OIDC; invite-only and normal account registration rules remain in force. If the Stoat account has MFA enabled, Stoat still prompts for it after OIDC authentication.

The API and web client must use the same host values configured in `hosts.api` and `hosts.app`. Redis stores the short-lived OAuth state and one-time login ticket; these expire after five minutes and ninety seconds respectively.
