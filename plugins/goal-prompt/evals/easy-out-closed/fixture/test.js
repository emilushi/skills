const { importRecords } = require("./src/importer");

const rows = importRecords("id=1;id=2");
if (!Array.isArray(rows) || rows.length !== 2) {
  console.error("importer broken");
  process.exit(1);
}
console.log("ok");
