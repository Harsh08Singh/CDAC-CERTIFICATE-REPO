const forge = require("node-forge");

// Load a certificate from raw PEM data
function loadCertificate(certPem) {
  return forge.pki.certificateFromPem(certPem);
}

// Verify the certificate chain
function verifyCertificateChain(
  caPem,
  chainPems,
  validityCheckDate = new Date()
) {
  const caCert = loadCertificate(caPem);
  const caStore = forge.pki.createCaStore([caCert]);
  const chain = chainPems.map(loadCertificate);

  const options = {
    validityCheckDate: validityCheckDate,
    verify: (verified, depth, certs) => {
      if (!verified) {
        console.log(`Certificate at depth ${depth} failed verification.`);
      }
      return verified;
    },
  };

  try {
    const verified = forge.pki.verifyCertificateChain(caStore, chain, options);
    if (verified === true) {
      console.log("Certificate chain is valid.");
    } else {
      console.log("Certificate chain is not valid.");
    }
  } catch (err) {
    console.error("Certificate chain verification failed:", err.message);
  }
}

module.exports = verifyCertificateChain;
