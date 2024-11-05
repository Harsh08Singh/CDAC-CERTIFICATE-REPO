// NOTE jsrasign

const forge = require("node-forge");
const fs = require("fs");
const path = require("path");
const jsrsasign = require("jsrsasign"); // Import jsrsasign

// Function to load a certificate from a file in PEM or DER format
function formatDate(dateStr) {
  // Date string in format "YYMMDDHHMMSSZ"
  // Example: "240828120000Z"
  const year = "20" + dateStr.slice(0, 2); // Convert to full year
  const month = dateStr.slice(2, 4);
  const day = dateStr.slice(4, 6);
  const hour = dateStr.slice(6, 8);
  const minute = dateStr.slice(8, 10);
  const second = dateStr.slice(10, 12);

  // Create a Date object in UTC
  return new Date(
    Date.UTC(year, month - 1, day, hour, minute, second)
  ).toLocaleString("en-US", { timeZone: "UTC" });
}

function loadCertificateFromFile(certPath) {
  const fileExtension = path.extname(certPath).toLowerCase();
  const certData = fs.readFileSync(certPath);

  if (fileExtension === ".pem") {
    // Certificate is in PEM format
    return { cert: certData.toString("utf8"), format: "pem" };
  } else if (fileExtension === ".der") {
    // Certificate is in DER format, convert it to PEM
    const certDer = Buffer.from(certData, "binary");
    const asn1 = forge.asn1.fromDer(certDer.toString("binary"));
    const certPem = forge.pki.certificateToPem(
      forge.pki.certificateFromAsn1(asn1)
    );
    return { cert: certPem, format: "pem" }; // Convert DER to PEM for consistent processing
  } else {
    throw new Error("Unsupported certificate file format");
  }
}

// Function to extract details from a certificate in PEM format using jsrsasign
function extractCertInfo(certPem) {
  let certInfo = {};

  try {
    // Using jsrsasign to extract certificate details
    const x = new jsrsasign.X509();
    x.readCertPEM(certPem);

    // certInfo.allInfo = x.getInfo();
    certInfo.commonName = x.getSubjectString().split("/CN=")[1] || "N/A";
    certInfo.issuerName = x.getIssuerString().split("/CN=")[1] || "N/A";
    certInfo.certSerialNumber = x.getSerialNumberHex();
    certInfo.validFrom = formatDate(x.getNotBefore());
    certInfo.validTo = formatDate(x.getNotAfter());
    certInfo.organization =
      x.getSubjectString().split("/O=")[1]?.split("/")[0] || "N/A"; // Organization
    certInfo.city =
      x.getSubjectString().split("/L=")[1]?.split("/")[0] || "N/A"; // City
    certInfo.country =
      x.getSubjectString().split("/C=")[1]?.split("/")[0] || "N/A"; // Country
    certInfo.certType = x.getExtKeyUsageString();
    certInfo.constraints = x.getExtBasicConstraints();
    // For handling OIDs other than RSA, we can extend this part if needed
    // Example: Extracting public key algorithm
    // const publicKey = x.getPublicKey();
    // certInfo.publicKeyAlgorithm = publicKey ? publicKey.alg : "N/A";
  } catch (error) {
    console.error("Error extracting certificate information:", error.message);
    throw error;
  }

  return certInfo;
}

// Function to extract information from a list of certificate files and sort by hierarchy
async function extractInfoFromCertFiles(certDir) {
  try {
    const certFiles = fs.readdirSync(certDir);
    const certFilePaths = certFiles
      .filter((file) => file.endsWith(".pem") || file.endsWith(".der"))
      .map((file) => path.join(certDir, file));

    const certInfos = certFilePaths
      .map((certFilePath) => {
        try {
          const { cert, format } = loadCertificateFromFile(certFilePath);
          const certInfo = extractCertInfo(cert);
          return {
            path: certFilePath,
            ...certInfo,
          };
        } catch (error) {
          console.error(
            "Failed to extract certificate information from file:",
            certFilePath,
            error.message
          );
          return null; // Return null or handle as needed
        }
      })
      .filter((info) => info !== null); // Filter out any failed extractions

    // Sort certificates by hierarchy level
    const sortedCertInfos = certInfos
      .filter((info) => info.path.endsWith(".pem"))
      .sort((a, b) => {
        const aLevel = (a.path.match(/cert_(\d+)_\d+\.pem/) || [])[1] || 0;
        const bLevel = (b.path.match(/cert_(\d+)_\d+\.pem/) || [])[1] || 0;
        return parseInt(bLevel, 10) - parseInt(aLevel, 10);
      });

    return sortedCertInfos;
  } catch (error) {
    console.error("Error processing certificate files:", error.message);
    throw error;
  }
}

// Exporting functions to be used in other files
module.exports = {
  loadCertificateFromFile,
  extractCertInfo,
  extractInfoFromCertFiles,
};
