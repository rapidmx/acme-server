# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-28

### Changed
- Initial commit
- Validate CAA answers with DNSSEC in-process: DnsChecks asks a CaaValidator (the new lib/dnssec DnssecResolver, chaining signatures from the IANA root trust anchors, proving denials with NSEC/NSEC3 and unsigned zones with an authenticated DS denial) at new-order and again at finalize, and refuses the order with a dns problem on a bogus or unprovable answer or after 30 seconds instead of falling back to an unvalidated one Add acme.dns.dnssec (validate by default) and refuse off outside development Test the validator against a synthetic signed hierarchy with attack, codec, crypto, transport and opt-in live (ACME_LIVE_DNS=1) suites, DnsChecks with a stub validator, and orders end to end with one Document the change in the CPS, architecture and deployment guides, the README, the release notes and NOTES, and remove SMTPUTF8, the operator API and DNSSEC from the not-implemented list
- Send certificate expiry reminders to the contacts of the ACME account that holds the certificate: 1 week, 3 days and 1 day before, at expiry, and 1 day and 1 week after while it has not been renewed, with none once a newer valid certificate for the same address and type exists or the certificate is revoked or the account is closed or has no usable contact Schedule each certificate's next reminder when it is issued (and on first run for older ones), claim a milestone with a conditional update so replicas never send it twice, retry a failed relay hourly, drop a reminder that is a day late, and send one e-mail per contact listing everything of the account that is due Add sendNotice to the mail transport, a per-contact daily budget (reminderMailsPerContactDay) and acme.reminders.enabled and batch_size settings Test the schedule, the message, and the whole flow with faked time, and report the port error when the DNSSEC transport test cannot bind Document the change in the architecture and deployment guides, the README, the release notes and NOTES
- Document that a downstream package's release bump level follows its upstream dependency's, minor for minor, patch for patch and major for major, in NOTES

[Unreleased]: https://github.com/rapidmx/acme-server/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rapidmx/acme-server/releases/tag/v0.2.0
