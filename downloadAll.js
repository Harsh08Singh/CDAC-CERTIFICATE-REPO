const express = require("express");
const bodyParser = require("body-parser");
const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const axios = require("axios");

const app = express();
const port = 3000;

// Define the base directory for storing downloaded certificates
const baseDir = path.join(__dirname, "caDownloaded");
if (!fs.existsSync(baseDir)) {
  fs.mkdirSync(baseDir);
}

app.use(bodyParser.json({ limit: "10mb" }));

// Function to download and convert a certificate
const downloadAndConvertCert = async (url, fileName) => {
  try {
    // Download the certificate
    const response = await axios({
      url: url,
      method: "GET",
      responseType: "arraybuffer", // Use arraybuffer to handle binary data
    });

    // Save the downloaded certificate
    const certFilePath = path.join(baseDir, fileName);
    fs.writeFileSync(certFilePath, response.data);
    // console.log(`Certificate downloaded and saved to ${certFilePath}`);

    // Convert DER to PEM if necessary
    const pemFilePath = certFilePath.replace(/\.der$/, ".pem");
    execSync(
      `openssl x509 -inform der -in "${certFilePath}" -out "${pemFilePath}"`
    );
    // console.log(
    //   `Certificate converted to PEM format and saved to ${pemFilePath}`
    // );

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
    // console.log("Certificate Information:\n", certText);

    // Extract the URLs of the issuing certificates
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

    // Process each URL
    for (const [index, url] of urls.entries()) {
      const fileName = `cert_${level}_${index + 1}.der`;
      const pemFilePath = await downloadAndConvertCert(url, fileName);

      // Recursively process the next level certificates
      await processCertificateChain(pemFilePath, level + 1);
    }
  } catch (error) {
    console.error("Error processing certificate chain:", error.message);
  }
};

// API endpoint to accept a raw certificate and process it
app.post("/process-certificate", async (req, res) => {
  try {
    const { rawCertificate } = req.body;

    if (!rawCertificate) {
      return res.status(400).json({ error: "Raw certificate is required." });
    }

    // Save the raw certificate
    const initialCertFile = path.join(baseDir, "initial_cert.pem");
    fs.writeFileSync(initialCertFile, rawCertificate);

    // Process the certificate chain
    await processCertificateChain(initialCertFile);

    res
      .status(200)
      .json({ message: "Certificate chain processed successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
