const forge = require("node-forge");

module.exports = {
  /**
   * Check if the raw certificate data contains the poison extension.
   * @param {string} certPem - The raw PEM-encoded certificate data.
   * @returns {boolean} - Returns true if the poison extension is found and is correct, otherwise false.
   */
  checkPoisonExtension: function (certPem) {
    try {
      // Convert PEM to an X.509 object
      const cert = forge.pki.certificateFromPem(certPem);

      // Find the poison extension
      const poisonExtension = cert.extensions.find(
        (ext) => ext.id === "1.3.6.1.4.1.11129.2.4.3"
      );
      console.log(poisonExtension);
      // Check if the poison extension is present and has the correct attributes
      if (
        !poisonExtension ||
        poisonExtension.critical !== true ||
        poisonExtension.value !== "\x05\x00"
      ) {
        console.log(
          "The pre-certificate is invalid or doesn't contain the correct poison extension."
        );
        return false;
      }

      // Poison extension found and correct
      console.log("The pre-certificate contains the correct poison extension.");
      return true;
    } catch (error) {
      console.error("Error checking poison extension:", error);
      throw new Error("Failed to check poison extension in certificate.");
    }
  },
};
