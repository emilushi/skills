const { legacyAuth } = require("./auth");

function refreshSession(token) {
  return legacyAuth(token.user, token.secret);
}

module.exports = { refreshSession };
