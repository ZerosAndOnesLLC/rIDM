//! Shared integration-test harness.
//!
//! One Postgres and one Redis per test binary, migrated once; every test gets
//! its own tenant and its own small connection pools so tests run in parallel
//! without interfering.
//!
//! Set `RIDM_TEST_DATABASE_URL` and `RIDM_TEST_REDIS_URL` to use existing
//! servers (CI service containers, or the docker-compose stack). Otherwise
//! testcontainers starts `postgres:18.6-alpine` and `redis:8.10.1-alpine3.23`
//! as named, reusable containers (`ridm-test-postgres`, `ridm-test-valkey`) that
//! later test binaries and runs pick up again. Remove them with
//! `docker rm -f ridm-test-postgres ridm-test-valkey`.

#![allow(dead_code)]

pub mod admin;
pub mod keycloak;
pub mod ldap;
pub mod throwaway;

mod harness;
pub use harness::*;
