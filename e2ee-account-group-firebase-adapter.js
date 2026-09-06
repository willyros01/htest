import {
  readCloudGroupAuthority,
  getCloudAccountE2EEPublicKey,
  createCloudGroupEpochRecord,
  readCloudGroupEpochRecord,
  sendCloudEncryptedGroupMessage
} from "./firebase.js";

// This adapter is intentionally thin. firebase.js remains the sole Firebase
// SDK owner; e2ee-account-group-runtime.js remains the sole group crypto
// orchestration owner. The adapter only translates their method names.
export function createFirebaseAccountGroupE2EETransport(){
  return Object.freeze({
    readGroupAuthority: readCloudGroupAuthority,
    getAccountPublicKey: getCloudAccountE2EEPublicKey,
    createGroupEpochRecord: createCloudGroupEpochRecord,
    readGroupEpochRecord: readCloudGroupEpochRecord,
    sendEncryptedGroupMessage: sendCloudEncryptedGroupMessage
  });
}
