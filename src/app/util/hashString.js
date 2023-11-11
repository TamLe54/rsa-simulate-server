const crypto = require('crypto')

const hasString = (inputString) => {
  const sha512 = crypto.createHash('sha512')

  sha512.update(inputString, 'utf-8')

  const hashedString = sha512.digest('hex')

  return hashedString
}

module.exports = hasString
