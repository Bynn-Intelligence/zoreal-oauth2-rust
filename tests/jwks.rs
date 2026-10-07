//! JWKS cache behaviour under failure and expiry.

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};
use zoreal_oauth2::{Client, ClientAuth};

fn short_ttl_client(p: &Provider, ttl: Duration) -> Client {
    Client::builder(CLIENT_ID)
        .issuer(p.issuer())
        .auth(ClientAuth::client_secret_basic(SECRET))
        .jwks_ttl(ttl)
        .build()
        .unwrap()
}

async fn jwks_ok_once_then_503(p: &Provider) {
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(&[&p.key])))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&p.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(2)
        .mount(&p.server)
        .await;
}

#[tokio::test]
async fn concurrent_logins_share_one_failed_fetch() {
    let p = Provider::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(100)))
        .mount(&p.server)
        .await;
    let client = p.client();
    let token = p.key.sign(&base_claims(&p.issuer()));

    let attempts = (0..50).map(|_| {
        let client = client.clone();
        let token = token.clone();
        tokio::spawn(async move { client.verify_id_token(&token, NONCE, None).await })
    });
    for attempt in attempts {
        let err = attempt.await.unwrap().unwrap_err();
        assert!(err.is_verification(), "{err:?}");
    }
    assert_eq!(p.requests_to("/jwks").await.len(), 1);

    // Within the failure backoff, a new login does not fetch either.
    assert!(client.verify_id_token(&token, NONCE, None).await.is_err());
    assert_eq!(p.requests_to("/jwks").await.len(), 1);
}

#[tokio::test]
async fn an_expired_set_is_served_while_refetching_fails() {
    let p = Provider::start().await;
    jwks_ok_once_then_503(&p).await;
    let client = short_ttl_client(&p, Duration::from_millis(200));
    let token = p.key.sign(&base_claims(&p.issuer()));
    client.verify_id_token(&token, NONCE, None).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    client.verify_id_token(&token, NONCE, None).await.unwrap();
    assert_eq!(p.requests_to("/jwks").await.len(), 2);
}

#[tokio::test]
async fn the_set_is_refreshed_ahead_of_expiry() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let client = short_ttl_client(&p, Duration::from_millis(500));
    let token = p.key.sign(&base_claims(&p.issuer()));
    client.verify_id_token(&token, NONCE, None).await.unwrap();

    // Past the soft TTL (80 %), before the TTL: served, and refreshed once.
    tokio::time::sleep(Duration::from_millis(430)).await;
    client.verify_id_token(&token, NONCE, None).await.unwrap();
    client.verify_id_token(&token, NONCE, None).await.unwrap();
    assert_eq!(p.requests_to("/jwks").await.len(), 2);
}

#[tokio::test]
async fn a_token_without_kid_verifies_against_a_single_key_set_only() {
    let p = Provider::start().await;
    let other = Key::generate("key-2");
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(&[&p.key])))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&p.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(&[&p.key, &other])))
        .with_priority(2)
        .mount(&p.server)
        .await;
    let token = p
        .key
        .sign_with_header(&json!({ "alg": "ES256" }), &base_claims(&p.issuer()));

    p.client()
        .verify_id_token(&token, NONCE, None)
        .await
        .unwrap();
    // A fresh client sees two keys: a kid-less token matches none of them.
    assert!(
        p.client()
            .verify_id_token(&token, NONCE, None)
            .await
            .is_err()
    );
}
