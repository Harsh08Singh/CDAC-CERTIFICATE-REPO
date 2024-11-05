const express = require("express");
const bodyParser = require("body-parser");
const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const { extractInfoFromCertFiles } = require("./extractCertificates.js");
const {
  verifyCertificateChainFromDir,
  readCertificates,
} = require("./certificateVerifier.js");
const {
  generateLogID,
  getCurrentTimestamp,
  generateSHA256Hash,
  derToPem,
  generatePreCertData,
} = require("./generateUniqueId.js");

const app = express();
const port = 3000;

// Define the base directory for storing downloaded certificates
const baseDir = path.join(__dirname, "caDownloaded");
if (!fs.existsSync(baseDir)) {
  fs.mkdirSync(baseDir);
}

app.use(bodyParser.json({ limit: "10mb" }));

// Function to delete all files in a directory
const deleteAllFilesInDirectory = (directory) => {
  try {
    const files = fs.readdirSync(directory);
    for (const file of files) {
      fs.unlinkSync(path.join(directory, file));
    }
    console.log(`All files deleted from directory: ${directory}`);
  } catch (error) {
    console.error(
      `Error deleting files in directory ${directory}:`,
      error.message
    );
  }
};
// Function to create a new list with desired fields
const createCertSummaryList = (certInfos) => {
  const summaryList = [];

  // Loop through the certInfos array
  for (let i = 0; i < certInfos.length; i++) {
    const cert = certInfos[i];
    const previousCert = certInfos[i - 1];

    // Create the summary object
    const summary = {
      CommonName: cert.commonName,
      SerialNumber: cert.certSerialNumber,
      IssuerCert_SrNo: previousCert
        ? previousCert.certSerialNumber
        : cert.certSerialNumber, // For root CA, use its own serial number
      IssuerCommonName: previousCert
        ? previousCert.commonName
        : cert.commonName, // For root CA, use its own common name
    };

    // Add the summary to the list
    summaryList.push(summary);
  }

  return summaryList;
};

// Function to download and convert a certificate
const downloadAndConvertCert = async (url, fileName) => {
  try {
    const response = await axios({
      url: url,
      method: "GET",
      responseType: "arraybuffer",
    });

    const certFilePath = path.join(baseDir, fileName);
    fs.writeFileSync(certFilePath, response.data);
    console.log(`Certificate downloaded and saved to ${certFilePath}`);

    const pemFilePath = certFilePath.replace(/\.der$/, ".pem");
    execSync(
      `openssl x509 -inform der -in "${certFilePath}" -out "${pemFilePath}"`
    );
    console.log(
      `Certificate converted to PEM format and saved to ${pemFilePath}`
    );

    return pemFilePath;
  } catch (error) {
    console.error(
      `Error downloading or converting certificate from ${url}:`,
      error.message
    );
    throw error;
  }
};

// Function to extract certificate URLs from a PEM file
const extractCertUrls = (certFile) => {
  try {
    const certText = execSync(
      `openssl x509 -in "${certFile}" -text`
    ).toString();
    console.log("Certificate Information:\n", certText);

    const urlRegex = /CA Issuers - URI:(\S+)/g;
    const urls = [];
    let match;
    while ((match = urlRegex.exec(certText)) !== null) {
      urls.push(match[1]);
    }

    return urls;
  } catch (error) {
    console.error("Error extracting certificate URLs:", error.message);
    throw error;
  }
};

// Recursive function to process the certificate chain
const processCertificateChain = async (certFile, level = 0) => {
  try {
    const urls = extractCertUrls(certFile);

    for (const [index, url] of urls.entries()) {
      const fileName = `cert_${level}_${index + 1}.der`;
      const pemFilePath = await downloadAndConvertCert(url, fileName);

      await processCertificateChain(pemFilePath, level + 1);
    }
  } catch (error) {
    console.error("Error processing certificate chain:", error.message);
  }
};

// Middleware to parse JSON bodies
app.use(express.json());

app.post("/process-certificate", async (req, res) => {
  try {
    const { certData } = req.body;

    if (!certData) {
      return res.status(400).json({ error: "certData is required." });
    }

    console.log("Base directory for certificates:", baseDir);

    const initialCertFile = path.join(baseDir, "initial_cert.pem");
    fs.writeFileSync(initialCertFile, certData);

    await processCertificateChain(initialCertFile);

    // Extract certificate information using the directory path
    const certInfos = await extractInfoFromCertFiles(baseDir);
    for (const certInfo of certInfos) {
      const { notBefore, notAfter } = certInfo;
      const currentDate = new Date();
      const startDate = new Date(notBefore);
      const endDate = new Date(notAfter);

      if (startDate > endDate) {
        return res.status(400).json({
          status: "Invalid date range",
          error: "The certificate's start date is after the end date.",
        });
      }

      if (currentDate < startDate) {
        return res.status(400).json({
          status: "Not yet valid",
          error: "The certificate is not valid yet.",
        });
      }

      if (currentDate > endDate) {
        return res.status(400).json({
          status: "Expired",
          error: "The certificate has expired.",
        });
      }
    }

    // Verify the certificate chain
    try {
      const isValid = verifyCertificateChainFromDir(baseDir);
      if (!isValid) {
        return res.status(400).json({ status: "Verification failed" });
      }
    } catch (error) {
      return res
        .status(400)
        .json({ status: "Verification failed", error: error.message });
    }
    // console.log(certInfos);
    const certSummaryList = createCertSummaryList(certInfos);
    console.log(certSummaryList);
    // Generate pre-certificate data
    const preCertData = generatePreCertData(certData, "pem");
    const expiredCerts = certInfos.filter((cert) => {
      const now = new Date();
      const validFrom = new Date(cert.validFrom);
      const validTo = new Date(cert.validTo);
      return now > validTo || now < validFrom || validTo < validFrom;
    });

    if (expiredCerts.length > 0) {
      return res.status(400).json({
        message:
          "Certificate chain processed but some certificates are expired or invalid.",
        certInfos,
        preCertData,
        expiredCerts,
      });
    }

    res.status(200).json({
      message: "Certificate chain processed and verified successfully.",
      certInfos,
      preCertData,
    });

    // Cleanup: Delete all downloaded certificates
    deleteAllFilesInDirectory(baseDir);
  } catch (error) {
    console.error("Error processing certificate:", error.message);
    res.status(500).json({ error: error.message });

    // Cleanup on error
    deleteAllFilesInDirectory(baseDir);
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
