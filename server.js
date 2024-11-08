const express = require("express");
const bodyParser = require("body-parser");
const { execSync } = require("child_process");
const fileUpload = require("express-fileupload");
const path = require("path");
const fs = require("fs");
const moment = require("moment");
const forge = require("node-forge");
const jsrsasign = require("jsrsasign");
const axios = require("axios");
const mysql = require("mysql2");
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

// Create MySQL connection
const connection = mysql.createConnection({
  host: "localhost",
  port: 4000,
  user: "root",
  password: "1234",
  database: "cdac3",
});

// Connect to the database
connection.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err);
    return;
  }
  console.log("Connected to the database");
});

const app = express();
const port = 3000;

// Define the base directory for storing downloaded certificates
const baseDir = path.join(__dirname, "caDownloaded");
if (!fs.existsSync(baseDir)) {
  fs.mkdirSync(baseDir);
}

app.use(bodyParser.json({ limit: "10mb" }));
app.use(fileUpload());
// Function to delete all files in a directory
const deleteAllFilesInDirectory = (directory) => {
  try {
    const files = fs.readdirSync(directory);
    for (const file of files) {
      fs.unlinkSync(path.join(directory, file));
    }
    // console.log(`All files deleted from directory: ${directory}`);
  } catch (error) {
    console.error(
      `Error deleting files in directory ${directory}:`,
      error.message
    );
  }
};

// Function to create a new list with desired fields
const createCertSummaryList = (certInfos) => {
  // for (let i = 0; i < certInfos.length; i++) {
  //   console.log(certInfos[i]);
  // }
  const summaryList = [];
  for (let i = 0; i < certInfos.length; i++) {
    const cert = certInfos[i];
    const previousCert = certInfos[i - 1];
    const summary = {
      SerialNumber: cert.certSerialNumber || "Unknown Serial Number",
      SubjectName: cert.commonName || "Unknown Subject Name",
      Organization: cert.organization || "Unknown Org",
      City: cert.city || "Unknown City",
      Country: cert.country || "Unknown Country",
      IssuerSlNo: previousCert
        ? previousCert.certSerialNumber || "Unknown Issuer Serial"
        : cert.certSerialNumber || "Unknown Serial Number",
      IssuerName: previousCert
        ? previousCert.commonName || "Unknown Issuer"
        : cert.commonName || "Unknown Subject Name",
      CAName: cert.organization || "Unknown CA", // Adjust if CAName maps differently
      IssuedDate: moment(cert.validFrom).format("YYYY-MM-DD HH:mm:ss"), // Formatted validFrom
      ExpiryDate: moment(cert.validTo).format("YYYY-MM-DD HH:mm:ss"), // Formatted validTo
      state: cert.state || "Unknown State", // Assuming cert.state exists
      certType: cert.certType || "NA", // Static value as specified
      constraints: cert.constraints,
      subjectType: cert.subjectType,
      Email: cert.email,
      X509Cert: cert.x509Cert,
      // validityPeriod: cert.validityPeriod,
    };

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
    // console.log(`Certificate downloaded and saved to ${certFilePath}`);

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
    // deleteAllFilesInDirectory(baseDir);
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

async function executeQuery(query, params = []) {
  return new Promise((resolve, reject) => {
    connection.query(query, params, (error, results) => {
      if (error) return reject(error);
      resolve(results);
    });
  });
}

async function checkPreCertificateInDatabase(certificate) {
  try {
    // Query to check if a certificate with the given primary keys already exists
    const checkQuery = `
      SELECT COUNT(*) AS count FROM precert 
      WHERE SerialNumber = ? AND IssuerName = ? AND IssuerSlNo = ?
    `;

    // Values for the check query
    const checkValues = [
      certificate.SerialNumber, // SerialNumber
      certificate.IssuerName, // IssuerName
      certificate.IssuerSlNo, // IssuerSlNo
    ];

    // Execute the check query
    const checkResult = await executeQuery(checkQuery, checkValues);

    // If the certificate already exists, return a message or handle as needed
    if (checkResult[0].count === 0) {
      throw new Error(
        "Pre-Certificate doesn't exist in the database for this certificate"
      );
    }
    console.log("Pre-Certificate Exists in the database");
  } catch (err) {
    console.error(err);
    throw new Error(`Error Occurred while checking database: ${err}`);
  }
}
async function insertCertificateInDatabase(certificate) {
  try {
    // SQL query to insert a new certificate record
    const query = `
      INSERT INTO cert (
        SerialNumber, IssueDate, ExpiryDate, CertType, IssuerSlNo, IssuerName, Country, Organization, State, SubjectName, Email, City, SubjectType, Fp_512, RawCertificate, CAname, ValidityPeriod
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Extract the relevant fields from certificate
    const values = [
      certificate.SerialNumber, // SerialNumber
      certificate.IssuedDate, // IssueDate
      certificate.ExpiryDate, // ExpiryDate
      "Signing",
      // certificate.certType, // CertType
      certificate.IssuerSlNo || "Unknown Issuer Serial", // IssuerSlNo
      certificate.IssuerName || "Unknown Issuer", // IssuerName
      certificate.Country || "Unknown Country", // Country
      certificate.Organization || "Unknown Org", // Organization
      certificate.state || "Unknown State", // State
      certificate.SubjectName, // SubjectName
      certificate.Email, // Email
      certificate.City || "Unknown City", // City
      certificate.subjectType, // SubjectType
      certificate.hash, // Fp_512 (using hash)
      certificate.X509Cert || "Unknown Certificate", // RawCertificate (using X509Cert)
      certificate.CAName || "Unknown CA", // CAname
      certificate.validityPeriod, // ValidityPeriod
    ];

    // Use the executeQuery function to run the query
    const result = await executeQuery(query, values);
    console.log("Certificate successfully stored in the database:", result);
  } catch (err) {
    console.error(err);
    throw new Error(`Error storing Certificate in the database: ${err}`);
  }
}

// const isValidX509 = (data) => {
//   try {
//     const certificate = forge.pki.certificateFromPem(data);
//     return certificate instanceof forge.pki.Certificate;
//   } catch (e) {
//     return false;
//   }
// };

const calculateValidityPeriod = function (issuedDate, expiryDate) {
  const startDate = new Date(issuedDate);
  const endDate = new Date(expiryDate);
  let years = endDate.getFullYear() - startDate.getFullYear();
  const months = endDate.getMonth() - startDate.getMonth();
  const days = endDate.getDate() - startDate.getDate();

  // Adjust the year count based on month and day
  if (months < 0 || (months === 0 && days < 0)) {
    years -= 1;
  }
  return years;
};

app.post("/process-certificate", async (req, res) => {
  try {
    // Check if a file was uploaded
    if (!req.files || !req.files.certificate) {
      return res.status(400).json({ error: "A certificate file is required." });
    }

    // Get the uploaded file
    const certificateFile = req.files.certificate;

    // Check the file extension
    const fileExtension = path.extname(certificateFile.name).toLowerCase();
    const allowedExtensions = [".cer", ".crt", ".pem"];
    if (!allowedExtensions.includes(fileExtension)) {
      return res.status(400).json({ error: "Invalid file extension." });
    }

    // Define the path to save the uploaded file
    const tempCertFile = path.resolve(baseDir, `temp_cert${fileExtension}`);
    const initialCertFile = path.resolve(baseDir, "initial_cert.pem");

    // Save the file to the server
    await certificateFile.mv(tempCertFile);

    // If the file is .crt or .cer, convert it to .pem
    if (fileExtension === ".crt" || fileExtension === ".cer") {
      try {
        // Use double quotes to handle spaces in file paths
        execSync(
          `openssl x509 -in "${tempCertFile}" -out "${initialCertFile}" -outform PEM`
        );
      } catch (error) {
        console.error("Error converting .crt/.cer to .pem:", error.message);
        return res
          .status(500)
          .json({ error: "Failed to convert certificate to PEM format." });
      }

      // Proceed with the certificate processing logic after conversion
      processCertificate(initialCertFile, res);
    } else {
      // If the file is already .pem, proceed directly
      fs.renameSync(tempCertFile, initialCertFile); // Rename the file to initial_cert.pem
      processCertificate(initialCertFile, res);
    }
  } catch (error) {
    console.error("Error processing certificate:", error.message);
    res.status(500).json({ error: error.message });

    // Cleanup on error
    deleteAllFilesInDirectory(baseDir);
  }
});

// Helper function to process the certificate
async function processCertificate(initialCertFile, res) {
  try {
    const certData = fs.readFileSync(initialCertFile, "utf8");

    // Using jsrsasign to extract certificate details
    const x = new jsrsasign.X509();
    x.readCertPEM(certData);

    // Continue processing the certificate chain
    await processCertificateChain(initialCertFile);

    const certInfos = await extractInfoFromCertFiles(baseDir);
    const certSummaryList = createCertSummaryList(certInfos);

    // Check for expired certificates
    const expiredCerts = certInfos.filter((cert) => {
      const now = new Date();
      const validFrom = new Date(cert.validFrom);
      const validTo = new Date(cert.validTo);
      return now > validTo || now < validFrom || validTo < validFrom;
    });

    if (expiredCerts.length > 0) {
      deleteAllFilesInDirectory(baseDir);
      return res.status(400).json({
        status: "Fail",
        message:
          "Certificate chain processed but some certificates are expired or invalid.",
        // certSummaryList,
        expiredCerts,
      });
    }
    const lastCert = certSummaryList[certSummaryList.length - 1];
    const preCertData = generatePreCertData(certData, "pem");
    lastCert.hash = preCertData.sha256Hash;
    lastCert.validityPeriod = calculateValidityPeriod(
      lastCert.IssuedDate,
      lastCert.ExpiryDate
    );

    //? Look for pre-certificate in the database
    await checkPreCertificateInDatabase(lastCert);

    //! BEGIN THE TRANSACTION
    connection.beginTransaction();

    //? Insert the Certificate into the database
    await insertCertificateInDatabase(lastCert);

    let args;
    // Validate from the blockchain

    // const argsToValidateFromBlockchain = {
    //   SerialNumber: lastCert.SerialNumber, // Assuming this field exists
    //   IssuserSlNo: lastCert.IssuerSlNo || "Unknown Issuer Serial",
    //   IssuserName: lastCert.IssuerName || "Unknown Issuer",
    //   Status: "Final",
    // };

    // console.log(
    //?   "Args To Validate from blockchain",
    //   argsToValidateFromBlockchain
    // );
    // args = { ...argsToValidateFromBlockchain };

    // const blockchainResponseForValidation = await verifyCertificateInBlockchain(
    //   args
    // );
    // if (blockchainResponseForValidation.status === "Success") {
    //   throw new Error(
    //     `Failed To validate from the blockchain: ${blockchainResponseForValidation.Message}`
    //   );
    // }

    // console.log(`Certificate present in the blockchain`);

    // Validate and check revoked certificates
    // const invalidCerts = await validateCertificates(certSummaryList);
    // const revokedCerts = await checkRevokedCertificates(certSummaryList);

    // if (invalidCerts.length > 0) {
    //   deleteAllFilesInDirectory(baseDir);
    //   return res.status(400).json({
    //     status: "Fail",
    //     message: "Some certificates are not issued by us.",
    //     invalidCertificates: invalidCerts,
    //     // initial: initialCertData,
    //   });
    // }

    // if (revokedCerts.length > 0) {
    //   return res.status(400).json({
    //     status: "Fail",
    //     message: "Some certificates have been revoked.",
    //     revokedCertificates: revokedCerts,
    //     // initial: initialCertData,
    //   });
    // }

    // Construct the args object dynamically
    const argsToStoreInBlockchain = {
      SerialNumber: lastCert.SerialNumber, // Assuming this field exists
      SubjectName: lastCert.SubjectName, // Assuming this field exists
      Organization: lastCert.Organization || "Unknown Org",
      City: lastCert.City || "Unknown City",
      Country: lastCert.Country || "Unknown Country",
      IssuserSlNo: lastCert.IssuerSlNo || "Unknown Issuer Serial",
      IssuserName: lastCert.IssuerName || "Unknown Issuer",
      CAName: lastCert.CAName || "Unknown CA",
      IssuedDate: lastCert.IssuedDate, // Formatted issued date
      ExpiryDate: lastCert.ExpiryDate, // Formatted expiry date
      Status: "Final",
      x509Cert: lastCert.X509Cert,
      Hash: lastCert.hash,
      state: lastCert.state || "Unknown State",
      certType: lastCert.certType,
      Email: lastCert.Email,
      subjectType: lastCert.subjectType,
      validityPeriod: lastCert.validityPeriod,
    };
    console.log("Args To store in blockchain", argsToStoreInBlockchain);
    args = { ...argsToStoreInBlockchain };
    //Store certificate in the blockchain
    // const blockchainResponseForStoringData = await storeInBlockchain(args);

    // if (blockchainResponseForStoringData.status !== 200) {
    //   throw new Error("Failed to store certificate in the blockchain");
    // }
    //! COMMIT THE TRANSACTION IF EVERYTHING IS SUCCESSFUL
    connection.commit();
    // Send the success response
    res.status(200).json({
      status: "Success",
      message:
        "Certificate verified and stored in the blockchain and database successfully.",
      // certSummaryList,
      // preCertData,
      // blockchainResponseForStoringData: blockchainResponseForStoringData.data,
    });

    // Cleanup: Delete all downloaded certificates
    deleteAllFilesInDirectory(baseDir);
  } catch (error) {
    //! ROLLBACK THE TRANSACTION IF ERROR OCCURRED
    connection.rollback();
    console.error("Error processing certificate:", error.message);
    res.status(500).json({ status: "Error", error: error.message });

    // Cleanup on error
    deleteAllFilesInDirectory(baseDir);
  }
}

// Function to verify whether the certificate is present in the blockchain
async function verifyCertificateInBlockchain(args) {
  try {
    const response = await axios.post(
      "http://10.244.0.197:9080/fabric/v1/invokecc",
      {
        fcn: "verifyCert",
        args,
      },
      {
        headers: {
          "x-access-token": "{{token}}",
          apikey: "d1c0d209b2c00e1cee448a703d639b4a0644a07b",
        },
      }
    );

    return response;
  } catch (error) {
    console.error("Error processing validation in blockchain:", error.message);
    throw error;
  }
}
// Function to store certificate in the blockchain
async function storeInBlockchain(args) {
  try {
    const response = await axios.post(
      "http://10.244.0.197:9080/fabric/v1/invokecc",
      {
        fcn: "RecordCert",
        args,
      },
      {
        headers: {
          "x-access-token": "{{token}}",
          apikey: "d1c0d209b2c00e1cee448a703d639b4a0644a07b",
        },
      }
    );

    return response;
  } catch (error) {
    console.error("Error storing in blockchain:", error.message);
    throw error;
  }
}
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
