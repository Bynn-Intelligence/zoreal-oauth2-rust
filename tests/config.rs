//! Client construction: every configuration mistake is a configuration error.

use zoreal_oauth2::{Client, ClientAuth, DEFAULT_ISSUER, Error, PrivateKey, TlsIdentity};

fn config_error(result: Result<Client, Error>) -> String {
    match result {
        Err(Error::Configuration { message, .. }) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

#[test]
fn the_issuer_defaults_to_production() {
    let client = Client::builder("ast_x").build().unwrap();
    assert_eq!(client.issuer(), DEFAULT_ISSUER);
    assert_eq!(client.client_id(), "ast_x");
}

#[test]
fn a_trailing_slash_is_trimmed_from_the_issuer() {
    let client = Client::builder("ast_x")
        .issuer("https://id.example.com/")
        .build()
        .unwrap();
    assert_eq!(client.issuer(), "https://id.example.com");
}

#[test]
fn a_client_id_is_required() {
    assert!(config_error(Client::builder("  ").build()).contains("client_id"));
}

#[test]
fn the_issuer_must_be_https_except_on_loopback() {
    assert!(
        config_error(
            Client::builder("ast_x")
                .issuer("http://id.example.com")
                .build()
        )
        .contains("https")
    );
    assert!(config_error(Client::builder("ast_x").issuer("not a url").build()).contains("URL"));
    assert!(
        config_error(
            Client::builder("ast_x")
                .issuer("https://id.example.com?x=1")
                .build()
        )
        .contains("query")
    );
    Client::builder("ast_x")
        .issuer("http://127.0.0.1:8080")
        .build()
        .unwrap();
    Client::builder("ast_x")
        .issuer("http://localhost:8080")
        .build()
        .unwrap();
}

#[test]
fn an_empty_secret_is_refused() {
    let result = Client::builder("ast_x")
        .auth(ClientAuth::client_secret_basic(""))
        .build();
    assert!(config_error(result).contains("secret"));
}

#[test]
fn zero_durations_and_a_large_leeway_are_refused() {
    use std::time::Duration;
    config_error(Client::builder("ast_x").timeout(Duration::ZERO).build());
    config_error(Client::builder("ast_x").jwks_ttl(Duration::ZERO).build());
    config_error(
        Client::builder("ast_x")
            .leeway(Duration::from_secs(600))
            .build(),
    );
}

#[test]
fn a_private_key_that_is_not_p256_is_a_configuration_error() {
    // A throwaway Ed25519 key, used only to prove a non-P-256 key is refused.
    let ed25519 = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIM4vDoOqGj1BWPpNqAumCDTozzdDmTLT1dfPqnGx/Vvv\n-----END PRIVATE KEY-----\n";
    assert!(
        PrivateKey::from_pem(ed25519)
            .unwrap_err()
            .is_configuration()
    );
    assert!(
        PrivateKey::from_pem("garbage")
            .unwrap_err()
            .is_configuration()
    );
    assert!(
        PrivateKey::from_pkcs8_der(&[0, 1, 2])
            .unwrap_err()
            .is_configuration()
    );
}

#[test]
fn a_tls_identity_that_does_not_parse_is_a_configuration_error() {
    let err = TlsIdentity::from_pem(b"not a certificate", &"not a key".into()).unwrap_err();
    assert!(err.is_configuration());
}

#[test]
fn the_secret_is_not_in_debug_output() {
    let client = Client::builder("ast_x")
        .client_secret("zcs_very_secret")
        .build()
        .unwrap();
    let rendered = format!("{client:?}");
    assert!(!rendered.contains("zcs_very_secret"));
    assert!(rendered.contains("ast_x"));
}

#[test]
fn the_client_is_send_sync_and_cheap_to_clone() {
    fn assert_send_sync<T: Send + Sync + Clone>() {}
    assert_send_sync::<Client>();
    fn assert_send<T: Send + Sync>() {}
    assert_send::<zoreal_oauth2::Login>();
    assert_send::<Error>();
}
