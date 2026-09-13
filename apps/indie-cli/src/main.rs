#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

use icc_capability_core::{AccessRequest, AuthorizationDecision, CapabilityGrant, authorize};
use icc_platform_api::Clock;
use icc_platform_linux::LinuxClock;
use icc_rights::Rights;
use icc_types::{AppId, Generation, MonotonicMs, ObjectId};

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("doctor") => doctor(),
        Some("demo") => demo(),
        _ => {
            eprintln!("usage: indie-cli <doctor|demo>");
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

    println!("architecture: phase3");
    println!("crypto_profile: classical-v1");
    println!("platform: linux");
    println!("wall_time_ms: {}", wall.get());
    println!("status: OK");
    ExitCode::SUCCESS
}

fn demo() -> ExitCode {
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

    println!("capability_read_decision: {decision:?}");

    if decision == AuthorizationDecision::Allow {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
