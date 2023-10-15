const crypto = require('crypto')

const decryption = (dataBuffer, privateKey, passphrase) => {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      passphrase: passphrase,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    dataBuffer
  )
}

module.exports = decryption
