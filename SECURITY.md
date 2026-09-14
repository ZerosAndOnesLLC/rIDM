# Security Policy

rIDM is an identity provider; security reports are treated as the highest priority.

## Supported versions

Until 1.0, only the latest minor release receives security fixes. After 1.0, the
current and previous minor release are supported.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private reporting:
<https://github.com/mack42/rIDM/security/advisories/new>

Include as much of the following as you can:

- A description of the issue and its impact.
- Steps to reproduce, a proof of concept, or the affected endpoint/flow.
- The version or commit you tested against.
- Whether you would like to be credited in the advisory.

You will receive an acknowledgement within **3 business days** and a plan (fix,
mitigation, or a reason it is not considered a vulnerability) within **10 business days**.

## Disclosure process

1. The report is triaged and reproduced privately.
2. A fix is developed on a private fork together with a regression test in
   `api/tests/security/`.
3. A GitHub Security Advisory with a CVE is published alongside the patched release.
4. Reporters are credited unless they prefer otherwise.

We ask for **90 days** from acknowledgement before public disclosure, or sooner once a
fix is released.

## Scope

In scope: everything in this repository (API, UI, deployment manifests, container
image, CLI, and published crates).

Out of scope: vulnerabilities in third-party dependencies that are already public
(report them upstream; we track them with `cargo audit` and `cargo deny`), and issues
that require a compromised host, database, or master key.

## security.txt

A machine-readable version of this policy is served at `/.well-known/security.txt`
(RFC 9116) by every rIDM deployment and lives in `api/src/routes/wellknown.rs`.
