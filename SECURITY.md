# Security policy

## Reporting a vulnerability

Please report security issues privately to **security@propia.id**, or through
GitHub's [private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository.

**Do not open a public issue.** This software issues and verifies government
identity credentials; a public report exposes real holders before a fix exists.

Please include what you need to make the problem reproducible: affected
component, version or commit, and the steps you took. If you have a proof of
concept, keep it in the private report.

## What to expect

- Acknowledgement within three working days.
- An assessment of severity and impact, shared with you.
- Coordinated disclosure: we agree a date with you before publishing, and
  credit you unless you prefer otherwise.

Please give us reasonable time to issue a fix before disclosing publicly.
Credentials already in citizens' hands cannot be recalled.

## Scope

In scope: the backend, the on-chain registries, and the SDKs in this
repository.

Out of scope: the deployed Propia services (report those the same way, but they
are operated infrastructure, not this source), third-party dependencies (report
upstream), and findings that require a compromised device or physical access to
an unlocked phone.
