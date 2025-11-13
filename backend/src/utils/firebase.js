// Firebase admin utilities have been disabled.
// This file remains only to avoid import errors in any leftover code paths.
// All auth and user management should use local JWT + MongoDB now.

const disabled = () => {
  throw new Error('Firebase utilities disabled — project migrated to MongoDB/JWT.');
};

module.exports = {
  verifyFirebaseToken: disabled,
  getFirebaseUser: disabled,
  createFirebaseUser: disabled,
};