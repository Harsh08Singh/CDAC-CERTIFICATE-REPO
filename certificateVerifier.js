// // certificateVerifier.js

// const fs = require("fs");
// const jsrsasign = require("jsrsasign");

// // Function to verify the certificate chain
// const verifyCertificateChain = (certificates) => {
//   let valid = true;

//   for (let i = 0; i < certificates.length - 1; i++) {
//     let cert = certificates[i];
//     let issuerCert = certificates[i + 1];

//     let certificate = new jsrsasign.X509();
//     certificate.readCertPEM(cert);

//     let issuerCertificate = new jsrsasign.X509();
//     issuerCertificate.readCertPEM(issuerCert);

//     // Get the certificate's signature and its signature algorithm
//     let certStruct = jsrsasign.ASN1HEX.getTLVbyList(certificate.hex, 0, [0]);
//     let algorithm = certificate.getSignatureAlgorithmField();
//     let signatureHex = certificate.getSignatureValueHex();

//     // Verify the certificate's signature with the issuer's public key
//     let Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
//     Signature.init(issuerCertificate.getPublicKey());
//     Signature.updateHex(certStruct);

//     if (!Signature.verify(signatureHex)) {
//       console.error(
//         `Certificate at index ${i} is not valid against its issuer.`
//       );
//       valid = false;
//       break;
//     }
//    }

//   return valid;
// };

// // Function to read certificates from file paths
// const readCertificates = (paths) => {
//   return paths.map((path) => fs.readFileSync(path, "utf8"));
// };

// // Export functions for use in other files
// module.exports = {
//   verifyCertificateChain,
//   readCertificates,
// };
// IMPORTANT
const fs = require("fs");
const path = require("path");
const jsrsasign = require("jsrsasign");

// Function to verify the certificate chain
const verifyCertificateChain = (certificates) => {
  let valid = true;

  for (let i = 0; i < certificates.length - 1; i++) {
    let cert = certificates[i];
    let issuerCert = certificates[i + 1];
    console.log("CERTIFICATE INFO ");
    let certificate = new jsrsasign.X509();
    // console.log(cert);
    certificate.readCertPEM(cert);

    let issuerCertificate = new jsrsasign.X509();
    issuerCertificate.readCertPEM(issuerCert);

    // Get the certificate's signature and its signature algorithm
    let certStruct = jsrsasign.ASN1HEX.getTLVbyList(certificate.hex, 0, [0]);
    let algorithm = certificate.getSignatureAlgorithmField();
    let signatureHex = certificate.getSignatureValueHex();

    // Verify the certificate's signature with the issuer's public key
    let Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
    Signature.init(issuerCertificate.getPublicKey());
    Signature.updateHex(certStruct);

    if (!Signature.verify(signatureHex)) {
      console.error(
        `Certificate at index ${i} is not valid against its issuer.`
      );
      valid = false;
      break;
    }
  }

  return valid;
};

// Function to verify the certificate chain from the directory
const verifyCertificateChainFromDir = (directory) => {
  try {
    const initialCertName = "initial_cert.pem";

    // Get all certificate files from the directory
    const certificateFiles = fs.readdirSync(directory);

    // Separate the end-entity certificate and CA certificates
    const endEntityCert = certificateFiles.find(
      (file) => file === initialCertName
    );
    const caCertificates = certificateFiles
      .filter((file) => file.endsWith(".pem") && file !== initialCertName)
      .sort((a, b) => a.localeCompare(b));

    // Ensure the end-entity certificate is first in the list
    const certificatePaths = [
      endEntityCert ? path.join(directory, endEntityCert) : null,
      ...caCertificates.map((file) => path.join(directory, file)),
    ].filter(Boolean);

    // Read certificates from file paths
    const certificates = readCertificates(certificatePaths);

    // Verify the certificate chain
    return verifyCertificateChain(certificates);
  } catch (error) {
    console.error("Error verifying certificate chain:", error.message);
    return false;
  }
};

// Function to read certificates from file paths
const readCertificates = (paths) => {
  return paths.map((path) => fs.readFileSync(path, "utf8"));
};

// Export functions for use in other files
module.exports = {
  verifyCertificateChain,
  verifyCertificateChainFromDir,
  readCertificates,
};
