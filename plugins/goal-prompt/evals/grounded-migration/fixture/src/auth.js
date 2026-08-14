// Legacy path, being phased out.
function legacyAuth(user, password) {
  return Boolean(user && password);
}

// Replacement API.
function verify(user, password) {
  return Boolean(user && password && password.length >= 6);
}

module.exports = { legacyAuth, verify };
