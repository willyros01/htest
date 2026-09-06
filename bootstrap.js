/* FIDUNIO deterministic bootstrap. Account/auth owners run before app.js. */
const {startAccountGuard}=await import("./account-guard.js");
await startAccountGuard();
const {runAuthGate}=await import("./auth-ui-clean.js");
await runAuthGate();
