## Repository classification — 2026-10-15

`willyros01/htest` is a **historical, isolated FIDUNIO authenticated-device test host**, not the production site or a current native migration branch. It remains pinned to its documented earlier Hermes rebuild source; its old PASS/FAIL statements are not applicable to the 2026-10-15 `hermes/Android` Amazon ADM migration or `hermes/ios` builds. No active merge, new release, testing deployment or production Firebase change is authorized by this documentation update. Current platform docs are branch-local to `hermes/main`, `main-3`, `ios` and `Android`; `htest` preserves the historical test snapshot.

---


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
