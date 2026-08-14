const { oldParse } = require("./parse");

function importRecords(blob) {
  return blob.split(";").map((chunk) => oldParse(chunk));
}

module.exports = { importRecords };
