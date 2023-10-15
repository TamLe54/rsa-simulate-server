const crypto = require('crypto')

const encryption = (dataBuffer, publicKey) => {
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Padding scheme
      oaepHash: 'sha256', // Algorithm for OAEP
    },
    dataBuffer
  )
}

module.exports = encryption
