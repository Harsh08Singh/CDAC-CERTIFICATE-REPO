const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const forge = require("node-forge");

// Function to generate a unique logID
function generateLogID() {
  return uuidv4();
}

// Function to get the current timestamp
function getCurrentTimestamp() {
  return new Date().toISOString();
}

// Function to generate a unique SHA-256 hash
function generateSHA256Hash(data) {
  const hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

// Function to convert DER to PEM
function derToPem(derBuffer, type) {
  const derBase64 = derBuffer.toString("base64");
  const pemHeader = `-----BEGIN ${type}-----`;
  const pemFooter = `-----END ${type}-----`;
  const pemBody = derBase64.match(/.{1,64}/g).join("\n");
  return `${pemHeader}\n${pemBody}\n${pemFooter}`;
}

// Function to generate pre-certificate data from raw certificate data
function generatePreCertData(certData, format = "pem") {
  let certPem;

  if (format === "pem") {
    // The certificate data is already in PEM format
    certPem = certData;
  } else if (format === "der") {
    // Convert DER-encoded certificate to PEM
    const certDer = Buffer.from(certData, "binary");
    const cert = forge.pki.certificateFromAsn1(
      forge.asn1.fromDer(certDer.toString("binary"))
    );
    certPem = forge.pki.certificateToPem(cert);
  } else {
    throw new Error("Unsupported certificate format");
  }

  // Generate the unique identifiers
  const logID = generateLogID();
  const timestamp = getCurrentTimestamp();
  const sha256Hash = generateSHA256Hash(certPem);

  return {
    logID,
    timestamp,
    sha256Hash,
  };
}

module.exports = {
  generateLogID,
  getCurrentTimestamp,
  generateSHA256Hash,
  derToPem,
  generatePreCertData,
};
