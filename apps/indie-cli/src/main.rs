#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

use icc_capability_core::{AccessRequest, AuthorizationDecision, CapabilityGrant, authorize};
use icc_crypto_api::{CryptoProviderV1, Ed25519SigningSeed};
use icc_crypto_rust::RustCryptoProviderV1;
use icc_identity_core::provision_local_identity_id;
use icc_platform_api::{Clock, SecureRandom};
use icc_platform_linux::{LinuxClock, LinuxSecureRandom};
use icc_rights::Rights;
use icc_types::{AppId, Generation, MonotonicMs, ObjectId};

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("doctor") => doctor(),
        Some("demo") => demo(),
        Some("crypto-demo") => crypto_demo(),
        _ => {
            eprintln!("usage: indie-cli <doctor|demo|crypto-demo>");
            ExitCode::from(2)
        }
    }
}

fn doctor() -> ExitCode {
    let clock = LinuxClock::new();
    let wall = match clock.wall_time_ms() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("clock: ERROR ({error})");
            return ExitCode::FAILURE;
        }
    };

    println!("architecture: phase2");
    println!("crypto_profile: classical-v1");
    println!("platform: linux");
    println!("wall_time_ms: {}", wall.get());
    println!("status: OK");
    ExitCode::SUCCESS
}

fn demo() -> ExitCode {
    let mut random = LinuxSecureRandom;
    let identity = match provision_local_identity_id(&mut random) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("identity provisioning failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    let app = AppId::from_bytes([0xA1; 16]);
    let object = ObjectId::from_bytes([0xB2; 16]);
    let grant = CapabilityGrant {
        subject: app,
        resource: object,
        rights: Rights::READ,
        generation: Generation::new(1),
        expires_at: Some(MonotonicMs::new(60_000)),
        delegable: false,
    };
    let request = AccessRequest {
        subject: app,
        resource: object,
        required: Rights::READ,
    };

    let decision = authorize(&grant, &request, MonotonicMs::new(1), Generation::new(1));

    println!("identity_id: {:02x?}", identity.id.as_bytes());
    println!("capability_read_decision: {decision:?}");

    if decision == AuthorizationDecision::Allow {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn crypto_demo() -> ExitCode {
    let provider = RustCryptoProviderV1;
    let mut random = LinuxSecureRandom;
    let mut seed_bytes = [0_u8; 32];

    if let Err(error) = random.fill(&mut seed_bytes) {
        eprintln!("entropy: ERROR ({error})");
        return ExitCode::FAILURE;
    }

    let signing_seed = Ed25519SigningSeed::from_bytes(seed_bytes);
    let public = provider.ed25519_public_from_seed(&signing_seed);
    let message = b"ICC/crypto-demo/v1\0hello";
    let signature = match provider.ed25519_sign(&signing_seed, message) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("signature: ERROR ({error})");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = provider.ed25519_verify(&public, message, &signature) {
        eprintln!("verify: ERROR ({error})");
        return ExitCode::FAILURE;
    }

    let digest = provider.sha256(message);
    println!("crypto_profile: classical-v1");
    println!("sha256: {:02x?}", digest.as_bytes());
    println!("ed25519_public: {:02x?}", public.as_bytes());
    println!("signature_verify: OK");
    ExitCode::SUCCESS
}
