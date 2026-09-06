import * as firebaseApi from "./firebase.js";

function requireMethod(api, name) {
  if (!api || typeof api[name] !== "function") throw new Error(`Missing Firebase account E2EE API method: ${name}`);
}

export function createFirebaseAccountE2EEIdentityStore(api = firebaseApi) {
  [
    "readCloudAccountE2EEIdentity",
    "createCloudAccountE2EEIdentity",
    "updateCloudAccountE2EENormalWrapper"
  ].forEach(name => requireMethod(api, name));

  return Object.freeze({
    readIdentity(uid) {
      return api.readCloudAccountE2EEIdentity(uid);
    },
    createIdentity({ uid, privateIdentity, publicIdentity }) {
      return api.createCloudAccountE2EEIdentity(uid, privateIdentity, publicIdentity);
    },
    updateNormalWrapper({ uid, keyId, expectedRevision, normalWrapper }) {
      return api.updateCloudAccountE2EENormalWrapper(uid, keyId, expectedRevision, normalWrapper);
    }
  });
}
