//! ID token verification: every rule, and every way a token is refused.

mod common;

use common::*;
use serde_json::json;
use zoreal_oauth2::{Acr, Error};

async fn verify(provider: &Provider, token: &str) -> Result<zoreal_oauth2::IdTokenClaims, Error> {
    provider.client().verify_id_token(token, NONCE, None).await
}

fn assert_verification(result: Result<impl std::fmt::Debug, Error>, needle: &str) {
    match result {
        Err(Error::Verification { reason, .. }) => {
            assert!(
                reason.contains(needle),
                "reason {reason:?} does not mention {needle:?}"
            )
        }
        other => panic!("expected a verification error mentioning {needle:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn a_valid_token_verifies_and_reads_typed_claims() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p.key.sign(&base_claims(&p.issuer()));

    let claims = verify(&p, &token).await.unwrap();
    assert_eq!(claims.sub, "TC5X-JN7G-YTSE-6E63");
    assert_eq!(claims.acr_level(), Some(Acr::Device));
    assert_eq!(claims.amr, ["hwk", "user"]);
    assert_eq!(claims.age_over(18), Some(true));
    assert_eq!(claims.age_over(21), None);
    assert_eq!(claims.nationality.as_deref(), Some("SWE"));
    let assurance = claims.assurance.unwrap();
    assert_eq!(
        assurance.uniqueness,
        Some(zoreal_oauth2::Uniqueness::PersonalNumber)
    );
    assert_eq!(assurance.trust_tier, Some(zoreal_oauth2::TrustTier::High));
    assert_eq!(
        assurance.key_protection,
        Some(zoreal_oauth2::KeyProtection::Strongbox)
    );
    assert_eq!(assurance.verified_on.as_deref(), Some("2026-08"));
}

#[tokio::test]
async fn unknown_assurance_values_do_not_fail_verification() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let claims = with(
        base_claims(&p.issuer()),
        json!({ "zoreal": { "uniqueness": "something_new", "key_protection": "quantum" } }),
    );
    let claims = verify(&p, &p.key.sign(&claims)).await.unwrap();
    let assurance = claims.assurance.unwrap();
    assert_eq!(
        assurance.uniqueness,
        Some(zoreal_oauth2::Uniqueness::Unknown)
    );
    assert_eq!(
        assurance.key_protection,
        Some(zoreal_oauth2::KeyProtection::Unknown)
    );
}

#[tokio::test]
async fn every_algorithm_but_es256_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let claims = base_claims(&p.issuer());
    for alg in ["none", "HS256", "RS256", "ES384", "PS256", "es256", "EdDSA"] {
        let token = p
            .key
            .sign_with_header(&json!({ "alg": alg, "kid": "key-1" }), &claims);
        assert_verification(verify(&p, &token).await, "only ES256");
    }
    let token = p.key.sign_with_header(&json!({ "kid": "key-1" }), &claims);
    assert_verification(verify(&p, &token).await, "no algorithm");
}

#[tokio::test]
async fn an_unsigned_none_token_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    use base64::Engine as _;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let token = format!(
        "{}.{}.",
        b64(json!({ "alg": "none" })),
        b64(base_claims(&p.issuer()))
    );
    assert_verification(verify(&p, &token).await, "only ES256");
}

#[tokio::test]
async fn a_critical_header_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p.key.sign_with_header(
        &json!({ "alg": "ES256", "kid": "key-1", "crit": ["exp"] }),
        &base_claims(&p.issuer()),
    );
    assert_verification(verify(&p, &token).await, "critical");
}

#[tokio::test]
async fn a_token_signed_by_another_key_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let impostor = Key::generate("key-1");
    let token = impostor.sign(&base_claims(&p.issuer()));
    assert_verification(verify(&p, &token).await, "signature does not verify");
}

#[tokio::test]
async fn a_tampered_payload_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p.key.sign(&base_claims(&p.issuer()));
    let forged = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "sub": "SOMEONE-ELSE" }),
    ));
    let parts: Vec<&str> = token.split('.').collect();
    let forged_parts: Vec<&str> = forged.split('.').collect();
    let spliced = format!("{}.{}.{}", parts[0], forged_parts[1], parts[2]);
    assert_verification(verify(&p, &spliced).await, "signature does not verify");
}

#[tokio::test]
async fn the_wrong_issuer_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    for iss in [
        "https://evil.example".to_owned(),
        format!("{}/", p.issuer()),
    ] {
        let token = p
            .key
            .sign(&with(base_claims(&p.issuer()), json!({ "iss": iss })));
        assert_verification(verify(&p, &token).await, "issuer");
    }
}

#[tokio::test]
async fn the_wrong_audience_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "aud": "ast_someoneelse" }),
    ));
    assert_verification(verify(&p, &token).await, "audience");

    // Several audiences need this client as the authorized party.
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "aud": [CLIENT_ID, "ast_other"] }),
    ));
    assert_verification(verify(&p, &token).await, "authorized party");
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "aud": [CLIENT_ID, "ast_other"], "azp": CLIENT_ID }),
    ));
    verify(&p, &token).await.unwrap();

    // A present azp must be this client, whatever the audience.
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "azp": "ast_other" }),
    ));
    assert_verification(verify(&p, &token).await, "authorized party");
}

#[tokio::test]
async fn an_expired_token_is_refused_beyond_the_leeway() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "exp": now() - 31 }),
    ));
    assert_verification(verify(&p, &token).await, "expired");

    // Within the 30-second leeway it still verifies.
    let token = p
        .key
        .sign(&with(base_claims(&p.issuer()), json!({ "exp": now() - 5 })));
    verify(&p, &token).await.unwrap();
}

#[tokio::test]
async fn a_token_without_exp_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p
        .key
        .sign(&with(base_claims(&p.issuer()), json!({ "exp": null })));
    assert_verification(verify(&p, &token).await, "malformed");
}

#[tokio::test]
async fn a_token_from_the_future_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "iat": now() + 600, "exp": now() + 720 }),
    ));
    assert_verification(verify(&p, &token).await, "future");
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "nbf": now() + 600 }),
    ));
    assert_verification(verify(&p, &token).await, "not valid yet");
}

#[tokio::test]
async fn the_nonce_is_mandatory_and_must_match() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let client = p.client();

    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "nonce": "another" }),
    ));
    assert_verification(client.verify_id_token(&token, NONCE, None).await, "nonce");

    let token = p
        .key
        .sign(&with(base_claims(&p.issuer()), json!({ "nonce": null })));
    assert_verification(client.verify_id_token(&token, NONCE, None).await, "nonce");

    let token = p.key.sign(&base_claims(&p.issuer()));
    assert_verification(
        client.verify_id_token(&token, "", None).await,
        "nonce is required",
    );
    assert_verification(
        client.verify_id_token(&token, "   ", None).await,
        "nonce is required",
    );
}

#[tokio::test]
async fn the_acr_floor_orders_session_below_device_below_live() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let client = p.client();
    let token_for = |acr: serde_json::Value| {
        p.key
            .sign(&with(base_claims(&p.issuer()), json!({ "acr": acr })))
    };

    // Below the floor.
    let device = token_for(json!("zoreal.device"));
    assert_verification(
        client
            .verify_id_token(&device, NONCE, Some(Acr::Live))
            .await,
        "below the required zoreal.live",
    );
    let session = token_for(json!("zoreal.session"));
    assert_verification(
        client
            .verify_id_token(&session, NONCE, Some(Acr::Device))
            .await,
        "below",
    );

    // At or above it.
    client
        .verify_id_token(&device, NONCE, Some(Acr::Device))
        .await
        .unwrap();
    let live = token_for(json!("zoreal.live"));
    client
        .verify_id_token(&live, NONCE, Some(Acr::Device))
        .await
        .unwrap();
    client
        .verify_id_token(&live, NONCE, Some(Acr::Live))
        .await
        .unwrap();

    // Missing or outside the vocabulary satisfies nothing.
    for acr in [json!(null), json!("zoreal.liveness"), json!("")] {
        let token = token_for(acr);
        assert_verification(
            client
                .verify_id_token(&token, NONCE, Some(Acr::Session))
                .await,
            "below",
        );
    }
}

#[tokio::test]
async fn an_unknown_required_acr_is_a_configuration_error() {
    let err = "zoreal.liveness".parse::<Acr>().unwrap_err();
    assert!(err.is_configuration(), "{err:?}");
    assert_eq!("zoreal.live".parse::<Acr>().unwrap(), Acr::Live);
}

#[tokio::test]
async fn the_jwks_is_cached() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let client = p.client();
    let token = p.key.sign(&base_claims(&p.issuer()));
    for _ in 0..3 {
        client.verify_id_token(&token, NONCE, None).await.unwrap();
    }
    assert_eq!(p.requests_to("/jwks").await.len(), 1);
}

#[tokio::test]
async fn an_unknown_kid_refetches_the_jwks_once_and_picks_up_the_rotated_key() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let p = Provider::start().await;
    let rotated = Key::generate("key-2");
    // The first fetch predates the rotation; later fetches carry both keys.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(&[&p.key])))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&p.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(&[&p.key, &rotated])))
        .with_priority(2)
        .mount(&p.server)
        .await;

    let client = p.client();
    client
        .verify_id_token(&p.key.sign(&base_claims(&p.issuer())), NONCE, None)
        .await
        .unwrap();
    assert_eq!(p.requests_to("/jwks").await.len(), 1);

    let token = rotated.sign(&base_claims(&p.issuer()));
    client.verify_id_token(&token, NONCE, None).await.unwrap();
    assert_eq!(p.requests_to("/jwks").await.len(), 2);

    // The rotated key is now cached: no further fetch.
    client.verify_id_token(&token, NONCE, None).await.unwrap();
    assert_eq!(p.requests_to("/jwks").await.len(), 2);
}

#[tokio::test]
async fn a_forged_kid_cannot_make_every_verification_fetch_the_jwks() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let client = p.client();
    let forger = Key::generate("forged");
    let token = forger.sign(&base_claims(&p.issuer()));
    for _ in 0..5 {
        assert_verification(client.verify_id_token(&token, NONCE, None).await, "no key");
    }
    // One fetch to fill the cache, one forced refetch, then nothing until
    // the refetch interval passes.
    assert_eq!(p.requests_to("/jwks").await.len(), 2);
}

#[tokio::test]
async fn a_jwks_that_cannot_be_fetched_is_a_verification_failure() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let p = Provider::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&p.server)
        .await;
    let token = p.key.sign(&base_claims(&p.issuer()));
    assert_verification(
        verify(&p, &token).await,
        "could not fetch the provider JWKS (503)",
    );
}

#[tokio::test]
async fn jwks_keys_of_other_shapes_are_skipped() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let p = Provider::start().await;
    let mut good = p.key.jwk();
    good["kid"] = json!("key-1");
    let off_curve =
        json!({ "kty": "EC", "crv": "P-256", "kid": "key-1", "x": "AAAA", "y": "AAAA" });
    let rsa = json!({ "kty": "RSA", "kid": "key-1", "n": "abc", "e": "AQAB" });
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "keys": [rsa, off_curve, good] })),
        )
        .mount(&p.server)
        .await;
    verify(&p, &p.key.sign(&base_claims(&p.issuer())))
        .await
        .unwrap();
}

#[tokio::test]
async fn malformed_tokens_are_refused_without_panicking() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let huge = "a".repeat(20_000);
    let inputs = [
        "",
        "not-a-jwt",
        "a.b",
        "a.b.c.d",
        "!!!.???.###",
        "eyJhbGciOiJFUzI1NiJ9.e30.AAAA",
        "eyJhbGciOiJFUzI1NiJ9..",
        "W10.e30.",
        huge.as_str(),
    ];
    for input in inputs {
        let result = verify(&p, input).await;
        assert!(
            matches!(result, Err(Error::Verification { .. })),
            "{input:.20}: {result:?}"
        );
    }
}

#[tokio::test]
async fn a_signed_payload_that_is_not_claims_is_refused() {
    let p = Provider::start().await;
    p.serve_jwks(&[&p.key]).await;
    let token = p.key.sign(&json!(["not", "an", "object"]));
    assert_verification(verify(&p, &token).await, "malformed");
    let token = p.key.sign(&with(
        base_claims(&p.issuer()),
        json!({ "zoreal": "not-a-block" }),
    ));
    assert_verification(verify(&p, &token).await, "malformed");
}
