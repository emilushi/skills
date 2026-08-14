const { verify } = require("./src/auth");
const { login } = require("./src/login");

if (typeof verify !== "function") {
  console.error("auth.verify missing");
  process.exit(1);
}
if (login("alice", "s3cret") !== true) {
  console.error("login flow broken");
  process.exit(1);
}
console.log("ok");
