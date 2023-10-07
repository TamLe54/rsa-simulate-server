const crypto = require('crypto')

const hasString = (inputString) => {
  // Create a new SHA-512 hash object
  const sha512 = crypto.createHash('sha512')

  // Update the hash object with the input string
  sha512.update(inputString, 'utf-8')

  // Get the hexadecimal representation of the hash
  const hashedString = sha512.digest('hex')

  return hashedString
}

module.exports = hasString
