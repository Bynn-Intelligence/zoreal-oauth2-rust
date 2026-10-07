//! The whole login, the code exchange, client authentication and userinfo.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::*;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};
use zoreal_oauth2::{Acr, ClientAuth, Error, ExposeSecret as _, PrivateKey};

fn form(request: &wiremock::Request) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

async fn serve_userinfo(p: &Provider, body: Value) {
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .and(header("authorization", "Bearer access-token-value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&p.server)
        .await;
}

#[tokio::test]
async fn authenticate_exchanges_verifies_and_reads_userinfo_lazily() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
    serve_userinfo(
        &p,
        json!({
            "sub": "TC5X-JN7G-YTSE-6E63",
            "email": "holder@example.com",
            "email_verified": true,
            "name": "Alex Holder",
            "given_name": "Alex",
            "family_name": "Holder",
        }),
    )
    .await;

    let login = p
        .client()
        .authenticate("the-code", "the-verifier", NONCE, None)
        .await
        .unwrap();
    assert_eq!(login.sub(), "TC5X-JN7G-YTSE-6E63");
    assert_eq!(login.acr(), Some("zoreal.device"));
    assert!(login.satisfies_acr(Acr::Device));
    assert!(!login.is_live());
    assert_eq!(login.scope(), Some("openid email profile.name"));
    assert!(
        p.requests_to("/userinfo").await.is_empty(),
        "userinfo must be lazy"
    );

    assert_eq!(login.email().await.unwrap(), Some("holder@example.com"));
    assert!(login.email_verified().await.unwrap());
    assert_eq!(login.name().await.unwrap(), Some("Alex Holder"));
    assert_eq!(login.family_name().await.unwrap(), Some("Holder"));
    assert_eq!(login.document_number().await.unwrap(), None);
    assert_eq!(
        p.requests_to("/userinfo").await.len(),
        1,
        "userinfo is fetched once"
    );

    // The exchange: form-encoded, client_id always in the form, the secret
    // only as HTTP Basic.
    let token_requests = p.requests_to("/token").await;
    assert_eq!(token_requests.len(), 1);
    let request = &token_requests[0];
    let form = form(request);
    assert_eq!(field(&form, "grant_type"), Some("authorization_code"));
    assert_eq!(field(&form, "code"), Some("the-code"));
    assert_eq!(field(&form, "code_verifier"), Some("the-verifier"));
    assert_eq!(field(&form, "client_id"), Some(CLIENT_ID));
    assert_eq!(field(&form, "client_secret"), None);
    let basic = format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{SECRET}")));
    assert_eq!(
        request
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        basic
    );
    assert!(
        request
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("application/x-www-form-urlencoded")
    );
}

#[tokio::test]
async fn email_verified_is_strictly_true() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
    serve_userinfo(
        &p,
        json!({ "sub": "TC5X-JN7G-YTSE-6E63", "email": "a@example.com", "email_verified": "true" }),
    )
    .await;
    let login = p
        .client()
        .authenticate("c", "v", NONCE, None)
        .await
        .unwrap();
    assert!(!login.email_verified().await.unwrap());
}

#[tokio::test]
async fn authenticate_refuses_an_acr_below_the_floor() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
    let err = p
        .client()
        .authenticate("c", "v", NONCE, Some(Acr::Live))
        .await
        .unwrap_err();
    assert!(err.is_verification(), "{err:?}");
}

#[tokio::test]
async fn authenticate_without_a_nonce_never_reaches_the_provider() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
    let err = p
        .client()
        .authenticate("c", "v", "", None)
        .await
        .unwrap_err();
    assert!(err.is_verification(), "{err:?}");
    assert!(p.requests_to("/token").await.is_empty());
}

#[tokio::test]
async fn a_missing_code_or_verifier_never_reaches_the_provider() {
    let p = Provider::start().await;
    let client = p.client();
    for (code, verifier) in [("", "v"), ("c", ""), (" ", "v")] {
        let err = client.exchange(code, verifier).await.unwrap_err();
        assert_eq!(err.oauth_error(), Some("invalid_request"));
    }
    assert!(p.requests_to("/token").await.is_empty());
}

#[tokio::test]
async fn a_provider_refusal_surfaces_verbatim() {
    let p = Provider::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            json!({ "error": "invalid_grant", "error_description": "the code is not valid" }),
        ))
        .mount(&p.server)
        .await;
    let err = p
        .client()
        .authenticate("spent-code", "v", NONCE, None)
        .await
        .unwrap_err();
    match &err {
        Error::Exchange {
            oauth_error,
            description,
            status,
            ..
        } => {
            assert_eq!(oauth_error, "invalid_grant");
            assert_eq!(description, "the code is not valid");
            assert_eq!(*status, Some(400));
        }
        other => panic!("expected an exchange error, got {other:?}"),
    }
    assert!(
        !err.to_string().contains("spent-code"),
        "the code must not appear in the error"
    );
}

#[tokio::test]
async fn a_non_json_failure_and_a_missing_id_token_are_exchange_errors() {
    let p = Provider::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(501).set_body_string("<html>not implemented</html>"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&p.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "access_token": "x" })))
        .with_priority(2)
        .mount(&p.server)
        .await;
    let client = p.client();

    let err = client.exchange("c", "v").await.unwrap_err();
    assert_eq!(err.oauth_error(), Some("server_error"));
    assert_eq!(err.status(), Some(501));

    let err = client.exchange("c", "v").await.unwrap_err();
    assert!(err.to_string().contains("no id_token"), "{err}");
}

#[tokio::test]
async fn private_key_jwt_signs_a_fresh_rfc7523_assertion() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;

    let client_key = Key::generate("rp-key");
    let pem = client_key.signing.to_pkcs8_pem(LineEnding::LF).unwrap();
    let auth = ClientAuth::PrivateKeyJwt(PrivateKey::from_pem(&pem).unwrap().with_kid("rp-key"));
    let client = p.client_with(auth);
    client.authenticate("c", "v", NONCE, None).await.unwrap();
    client.exchange("c", "v").await.unwrap();

    let requests = p.requests_to("/token").await;
    assert_eq!(requests.len(), 2);
    let mut jtis = Vec::new();
    for request in &requests {
        assert!(
            request.headers.get("authorization").is_none(),
            "no Basic header with private_key_jwt"
        );
        let form = form(request);
        assert_eq!(field(&form, "client_id"), Some(CLIENT_ID));
        assert_eq!(
            field(&form, "client_assertion_type"),
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        );
        let assertion = field(&form, "client_assertion").unwrap();
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "rp-key");

        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        let verifying: &VerifyingKey = client_key.signing.verifying_key();
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();

        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], CLIENT_ID);
        assert_eq!(claims["sub"], CLIENT_ID);
        assert_eq!(claims["aud"], format!("{}/token", p.issuer()));
        let iat = claims["iat"].as_i64().unwrap();
        assert_eq!(claims["exp"].as_i64().unwrap() - iat, 50);
        assert!((iat - now()).abs() < 5);
        jtis.push(claims["jti"].as_str().unwrap().to_owned());
    }
    assert_ne!(jtis[0], jtis[1], "every assertion carries a fresh jti");
}

#[tokio::test]
async fn a_sec1_pem_key_is_accepted_too() {
    use p256::elliptic_curve::Generate as _;
    let secret = p256::SecretKey::generate();
    let pem = secret.to_sec1_pem(LineEnding::LF).unwrap();
    PrivateKey::from_pem(&pem).unwrap();
}

#[tokio::test]
async fn a_public_client_sends_no_authorization_header() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
    p.client_with(ClientAuth::None)
        .authenticate("c", "v", NONCE, None)
        .await
        .unwrap();
    let request = &p.requests_to("/token").await[0];
    assert!(request.headers.get("authorization").is_none());
    assert_eq!(field(&form(request), "client_id"), Some(CLIENT_ID));
}

#[tokio::test]
async fn a_userinfo_failure_is_a_userinfo_error_and_is_retried() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({ "error": "invalid_token", "error_description": "the access token is not valid" })),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&p.server)
        .await;
    serve_userinfo(
        &p,
        json!({ "sub": "TC5X-JN7G-YTSE-6E63", "email": "holder@example.com" }),
    )
    .await;

    let login = p
        .client()
        .authenticate("c", "v", NONCE, None)
        .await
        .unwrap();
    match login.email().await.unwrap_err() {
        Error::Userinfo {
            description,
            status,
            ..
        } => {
            assert_eq!(description, "the access token is not valid");
            assert_eq!(status, Some(401));
        }
        other => panic!("expected a userinfo error, got {other:?}"),
    }
    // The login itself is still usable, and a failure is not cached.
    assert_eq!(login.sub(), "TC5X-JN7G-YTSE-6E63");
    assert_eq!(login.email().await.unwrap(), Some("holder@example.com"));
}

#[tokio::test]
async fn a_userinfo_response_for_another_subject_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
    serve_userinfo(
        &p,
        json!({ "sub": "SOME-ONE-ELSE", "email": "x@example.com" }),
    )
    .await;
    let login = p
        .client()
        .authenticate("c", "v", NONCE, None)
        .await
        .unwrap();
    assert!(login.email().await.unwrap_err().is_userinfo());
}

#[tokio::test]
async fn a_userinfo_response_without_a_string_subject_is_refused() {
    for body in [
        json!({ "email": "x@example.com" }),
        json!({ "sub": 1, "email": "x@example.com" }),
    ] {
        let p = Provider::start().await;
        p.serve_jwks(&[&p.key]).await;
        p.serve_token(&p.key.sign(&base_claims(&p.issuer()))).await;
        serve_userinfo(&p, body).await;
        let login = p
            .client()
            .authenticate("c", "v", NONCE, None)
            .await
            .unwrap();
        assert!(login.email().await.unwrap_err().is_userinfo());
    }
}

#[tokio::test]
async fn userinfo_is_empty_without_an_access_token() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id_token": p.key.sign(&base_claims(&p.issuer())) })),
        )
        .mount(&p.server)
        .await;
    let login = p
        .client()
        .authenticate("c", "v", NONCE, None)
        .await
        .unwrap();
    assert_eq!(login.email().await.unwrap(), None);
    assert!(p.requests_to("/userinfo").await.is_empty());
}

#[tokio::test]
async fn the_userinfo_step_is_public_too() {
    let p = Provider::start().await;
    serve_userinfo(
        &p,
        json!({ "sub": "TC5X-JN7G-YTSE-6E63", "birthdate": "1990-01-31" }),
    )
    .await;
    let info = p
        .client()
        .userinfo(&"access-token-value".into())
        .await
        .unwrap();
    assert_eq!(info.birthdate(), Some("1990-01-31"));
    assert!(
        !format!("{info:?}").contains("1990"),
        "Debug lists claim names, not values"
    );
}

#[tokio::test]
async fn an_oversized_response_is_refused() {
    let p = Provider::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(512 * 1024)))
        .mount(&p.server)
        .await;
    let err = p.client().exchange("c", "v").await.unwrap_err();
    assert!(err.is_exchange(), "{err:?}");
}

#[tokio::test]
async fn secrets_and_tokens_stay_out_of_debug_output() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let id_token = p.key.sign(&base_claims(&p.issuer()));
    p.serve_token(&id_token).await;
    let client = p.client();
    assert!(!format!("{client:?}").contains(SECRET));

    let tokens = client.exchange("c", "v").await.unwrap();
    let rendered = format!("{tokens:?}");
    assert!(!rendered.contains("access-token-value") && !rendered.contains(&id_token));
    assert_eq!(
        tokens.access_token.as_ref().unwrap().expose_secret(),
        "access-token-value"
    );

    let login = client.authenticate("c", "v", NONCE, None).await.unwrap();
    let rendered = format!("{login:?}");
    assert!(
        !rendered.contains("access-token-value")
            && !rendered.contains(&id_token)
            && !rendered.contains(NONCE)
            && !rendered.contains("SWE")
    );

    let key = Key::generate("k");
    let pem = key.signing.to_pkcs8_pem(LineEnding::LF).unwrap();
    let private = PrivateKey::from_pem(&pem).unwrap();
    let rendered = format!("{private:?}");
    assert!(rendered.contains("REDACTED") && !rendered.contains(pem.lines().nth(1).unwrap()));
}
