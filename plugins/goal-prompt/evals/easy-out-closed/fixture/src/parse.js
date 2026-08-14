// Deprecated: use parseRecord instead.
function oldParse(raw) {
  return raw.split("=")[1];
}

function parseRecord(raw) {
  const [key, value] = raw.split("=");
  if (!key || value === undefined) throw new Error("malformed record");
  return value;
}

module.exports = { oldParse, parseRecord };
