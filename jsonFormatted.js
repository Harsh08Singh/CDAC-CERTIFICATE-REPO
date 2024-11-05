const fs = require("fs");
const path = require("path");

// Path to the certificate file
const certFilePath = path.join(__dirname, "TEST CERTIFICATES/5.cer");

// Path to the directory where the JSON file will be saved
const jsonDirPath = path.join(__dirname, "JSONRequests");

// Create the JSONRequests directory if it doesn't exist
if (!fs.existsSync(jsonDirPath)) {
  fs.mkdirSync(jsonDirPath, { recursive: true });
}

// Read the certificate file
fs.readFile(certFilePath, "utf8", (err, data) => {
  if (err) {
    console.error("Error reading certificate file:", err);
    return;
  }

  // Create JSON object with the certData field
  const jsonObject = {
    certData: data,
  };

  // Path to the output JSON file
  const jsonFilePath = path.join(jsonDirPath, "certificate.json");

  // Write the JSON object to the file
  fs.writeFile(jsonFilePath, JSON.stringify(jsonObject, null, 2), (err) => {
    if (err) {
      console.error("Error writing JSON file:", err);
    } else {
      console.log("JSON file saved successfully:", jsonFilePath);
    }
  });
});
