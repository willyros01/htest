// FIDUNIO account E2EE v1 Firestore adapter.
// This module owns only the durable account-identity documents. It receives the
// already-initialized Firebase services from firebase.js; it never initializes Firebase.

function requireAuthUid(authUser, uid) {
  if (!authUser || authUser.uid !== uid) throw new Error("Authenticated account does not match E2EE identity owner.");
}

export function createAccountE2EEFirestoreAdapter({ db, fsSdk, getAuthUser }) {
  if (!db || !fsSdk || typeof getAuthUser !== "function") throw new Error("Firestore adapter dependencies are incomplete.");
  const privateRef = uid => fsSdk.doc(db, "users", uid, "e2ee", "identity");
  const publicRef = uid => fsSdk.doc(db, "e2eePublicKeys", uid);

  return Object.freeze({
    async readIdentity(uid) {
      requireAuthUid(getAuthUser(), uid);
      const snap = await fsSdk.getDoc(privateRef(uid));
      return snap.exists() ? { ...snap.data() } : null;
    },

    async createIdentity({ uid, privateIdentity, publicIdentity }) {
      requireAuthUid(getAuthUser(), uid);
      const pRef = privateRef(uid), pubRef = publicRef(uid);
      const result = await fsSdk.runTransaction(db, async tx => {
        const [pSnap, pubSnap] = await Promise.all([tx.get(pRef), tx.get(pubRef)]);
        if (pSnap.exists() || pubSnap.exists()) throw new Error("Durable E2EE identity already exists or is partially established; automatic replacement is forbidden.");
        const now = fsSdk.serverTimestamp();
        tx.set(pRef, { ...privateIdentity, createdAt: now, updatedAt: now });
        tx.set(pubRef, { ...publicIdentity, createdAt: now, updatedAt: now });
        return { revision: 1 };
      });
      return result;
    },

    async updateNormalWrapper({ uid, keyId, expectedRevision, normalWrapper }) {
      requireAuthUid(getAuthUser(), uid);
      const ref = privateRef(uid);
      return fsSdk.runTransaction(db, async tx => {
        const snap = await tx.get(ref);
        if (!snap.exists()) throw new Error("Durable E2EE identity is missing.");
        const current = snap.data();
        if (current.keyId !== keyId) throw new Error("E2EE identity keyId changed; update aborted.");
        if (current.revision !== expectedRevision) throw new Error("E2EE identity revision changed; reload before retrying.");
        tx.update(ref, { normalWrapper, revision: expectedRevision + 1, updatedAt: fsSdk.serverTimestamp() });
        return { revision: expectedRevision + 1 };
      });
    }
  });
}
