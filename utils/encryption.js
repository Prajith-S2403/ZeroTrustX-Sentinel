const crypto = require("crypto");
const fs = require("fs");

const algorithm = "aes-256-cbc";
const secretKey = crypto
  .createHash("sha256")
  .update("zerotrust-file-encryption-key")
  .digest();

function encryptFile(filePath) {
  const iv = crypto.randomBytes(16);

  const input = fs.createReadStream(filePath);
  const output = fs.createWriteStream(filePath + ".enc");

  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);

  input.pipe(cipher).pipe(output);

  return new Promise((resolve, reject) => {
    output.on("finish", () => {
      fs.unlinkSync(filePath);

      resolve({
        encryptedPath: filePath + ".enc",
        iv: iv.toString("hex"),
      });
    });

    output.on("error", reject);
  });
}

function decryptFile(encryptedPath, ivHex, outputPath) {
  const iv = Buffer.from(ivHex, "hex");

  const input = fs.createReadStream(encryptedPath);
  const output = fs.createWriteStream(outputPath);

  const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);

  input.pipe(decipher).pipe(output);

  return new Promise((resolve, reject) => {
    output.on("finish", () => resolve(outputPath));
    output.on("error", reject);
  });
}

module.exports = {
  encryptFile,
  decryptFile,
};