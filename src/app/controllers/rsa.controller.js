// const { error } = require('console')
const supabase = require('../config')
const crypto = require('crypto')
const hasString = require('../util/hashString')
const getBitLength = require('../util/getBitLength')

class RSAController {
  generateKey(req, res, next) {
    const { email, password } = req.body

    // Create randomly salt
    const salt = crypto.randomBytes(32)

    // Use PBKDF2 to create a secrect key from password
    crypto.pbkdf2(password, salt, 10000, 32, 'sha512', async (err, key) => {
      if (err) throw err

      try {
        await supabase.from('RSA_Account').upsert(
          {
            email: email,
            hashPassword: hasString(password),
            passphrase: key.toString('hex'),
          },
          {
            onConflict: ['email'],
          }
        )

        crypto.generateKeyPair(
          'rsa',
          {
            modulusLength: 4096, // the key length
            publicKeyEncoding: {
              type: 'spki',
              format: 'pem',
            },
            privateKeyEncoding: {
              type: 'pkcs8',
              format: 'pem',
              cipher: 'aes-256-cbc', //Cipher the private key
              passphrase: key.toString('hex'), // use the secret key above to hide the private key
            },
          },
          (err, publicKey, privateKey) => {
            if (err) {
              throw err
              next(err)
            }

            return res.status(200).json({
              publicKey: publicKey,
              privateKey: privateKey,
            })
          }
        )
      } catch (err) {
        throw err
      }

      // Create RSA key pars
    })
  }

  encrypt(req, res, next) {
    const { publicKey, dataToEncrypt } = req.body

    try {
      const encryptedData = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Padding scheme
          oaepHash: 'sha256', // Algorithm for OAEP
        },
        Buffer.from(dataToEncrypt)
      )
      return res.status(200).json({
        encryptedData: encryptedData.toString('base64'),
      })
    } catch (err) {
      throw err
    }
  }

  async decrypt(req, res, next) {
    const { email, privateKey, password, encryptedData } = req.body
    const hashPassword = hasString(password)

    const decodedBuffer = Buffer.from(encryptedData, 'base64')

    try {
      const { data, error } = await supabase
        .from('RSA_Account')
        .select('passphrase')
        .eq('email', email)
        .eq('hashPassword', hashPassword)

      if (error) {
        return res.status(500).json({
          success: 'false',
          message: 'Error ocurred when checking',
        })
      }

      if (data.length === 0) {
        return res.status(404).json({
          success: 'false',
          message: 'Email or Password is incorrect',
        })
      }

      const passphrase = data[0].passphrase
      console.log(passphrase)

      const decryptedData = crypto.privateDecrypt(
        {
          key: privateKey,
          passphrase: passphrase,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        decodedBuffer
      )

      return res.status(200).json({
        success: 'true',
        decryptedData: decryptedData.toString('utf-8'),
      })
    } catch (err) {
      throw err
    }
  }
}

module.exports = new RSAController()
