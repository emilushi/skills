const { legacyAuth } = require("./auth");

function login(user, password) {
  return legacyAuth(user, password);
}

module.exports = { login };
