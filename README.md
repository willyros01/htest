# htest

Isolated FIDUNIO authenticated-device test host. This is not the production repository.

- Visible test version: 0.9.6.4
- Application source is immutably pinned to Hermes rebuild commit `bda5efee19333b4b3a3108341d30431d20447754`.
- Hermes `main` is not used or modified by this test host.
- Firebase App Check enforcement remains OFF during this validation stage.
- The test host contains no recovery master secret, service-account credential, server recovery source, or private key material.
- `service-worker.js` is a test-host cache/transport wrapper only and performs no application source transformation.
- Diagnostics: `test-diagnostics.html`.

The 0.9.6.4 source head is for controlled live-device validation. The predecessor 0.9.6.3 security checkpoint was green; do not describe 0.9.6.4 as an exact-head green CI result unless a matching workflow run is later recorded.
