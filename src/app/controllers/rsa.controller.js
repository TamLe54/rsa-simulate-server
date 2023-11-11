const supabase = require('../config')
const crypto = require('crypto')
const hasString = require('../util/hashString')
const encryption = require('../util/encrypt')
const decryption = require('../util/decrypt')
const { MODULE_LENGTH, STRING_TYPE } = require('../constants')
const bufferHandle = require('../util/bufferHandle')

class RSAController {
  generateKey(req, res, next) {
    console.log('Starting key generating....')
    const { email, password } = req.body

    const salt = crypto.randomBytes(32)

    crypto.pbkdf2(password, salt, 10000, 32, 'sha512', async (err, key) => {
      if (err) throw err

      try {
        await supabase.from('RSA_Account').upsert(
          {
            email: email,
            hashPassword: hasString(password),
            passphrase: key.toString(STRING_TYPE.HEX),
          },
          {
            onConflict: ['email'],
          }
        )

        crypto.generateKeyPair(
          'rsa',
          {
            modulusLength: MODULE_LENGTH,
            publicKeyEncoding: {
              type: 'spki',
              format: 'pem',
            },
            privateKeyEncoding: {
              type: 'pkcs8',
              format: 'pem',
              cipher: 'aes-256-cbc',
              passphrase: key.toString(STRING_TYPE.HEX),
            },
          },
          (err, publicKey, privateKey) => {
            if (err) {
              throw err
              next(err)
            }
            console.log('Complete Generating')
            return res.status(200).json({
              publicKey: publicKey,
              privateKey: privateKey,
            })
          }
        )
      } catch (err) {
        throw err
      }
    })
  }

  encrypt(req, res) {
    const { publicKey, dataToEncrypt } = req.body

    console.log('Starting Encryption...')

    try {
      const chunks = bufferHandle.splitUTF8(dataToEncrypt)

      const encryptedChunks = chunks.map((chunk) =>
        encryption(chunk, publicKey)
      )

      const encryptedData = bufferHandle
        .join(encryptedChunks)
        .toString(STRING_TYPE.BASE64)

      console.log('Completed Encryption')

      return res.status(200).json({
        encryptedData: encryptedData,
      })
    } catch (err) {
      throw err
    }
  }

  async decrypt(req, res, next) {
    const { email, privateKey, password, encryptedData } = req.body

    console.log('Starting Decryption....')

    const hashPassword = hasString(password)

    try {
      const { data, error } = await supabase
        .from('RSA_Account')
        .select('passphrase')
        .eq('email', email)
        .eq('hashPassword', hashPassword)

      if (error) {
        return res.status(500).json({
          success: 'false',
          message: 'Error ocurred when checking database',
        })
      }

      if (data.length === 0) {
        return res.status(404).json({
          success: 'false',
          message: 'Email or Password is incorrect',
        })
      }

      const passphrase = data[0].passphrase
      const chunks = bufferHandle.splitBase64(encryptedData)

      const decryptedChunks = chunks.map((chunk) =>
        decryption(chunk, privateKey, passphrase)
      )

      const decryptedData = bufferHandle
        .join(decryptedChunks)
        .toString(STRING_TYPE.UTF8)

      console.log('Completed Decryption!')

      return res.status(200).json({
        success: 'true',
        decryptedData: decryptedData,
      })
    } catch (err) {
      throw err
    }
  }
}

module.exports = new RSAController()
