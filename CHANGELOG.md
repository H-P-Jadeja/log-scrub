# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-08
### Added
- `scrub`, `scrubString`, `createScrubber` APIs
- Key-based and pattern-based redaction (JWT, Bearer, AWS, GitHub, URL credentials, credit cards, email)
- `expressMiddleware` adding `req.scrubbed()`
- TypeScript type definitions
