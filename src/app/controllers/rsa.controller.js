const supabase = require('../config')
const crypto = require('crypto')
const hasString = require('../util/hashString')
const encryption = require('../util/encrypt')
const decryption = require('../util/decrypt')
const { MODULE_LENGTH } = require('../constants')
const bufferHandle = require('../util/bufferHandle')

class RSAController {
  generateKey(req, res, next) {
    console.log('Starting key generating....')
    const { email, password } = req.body

    //* Create randomly salt
    const salt = crypto.randomBytes(32)

    //* Use PBKDF2 to create a secret key from password
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
            modulusLength: MODULE_LENGTH, // the key length
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

      // Create RSA key pars
    })
  }

  encrypt(req, res) {
    const { publicKey, dataToEncrypt } = req.body

    console.log('Starting Encryption...')

    try {
      //* split the data into smaller buffers
      const chunks = bufferHandle.splitUTF8(dataToEncrypt)

      //* encrypt each chunk of buffer
      const encryptedChunks = chunks.map((chunk) =>
        encryption(chunk, publicKey)
      )

      //* join the encrypted buffers into one buffer and convert to base64 string
      const encryptedData = bufferHandle
        .join(encryptedChunks)
        .toString('base64')

      console.log('Completed Encryption')

      //* return the base64 string
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

    //* hash the gotten password
    const hashPassword = hasString(password)

    try {
      //*compare the hash with the hash in database corresponding with email
      const { data, error } = await supabase
        .from('RSA_Account')
        .select('passphrase')
        .eq('email', email)
        .eq('hashPassword', hashPassword)

      //* return the error if checking process is down
      if (error) {
        return res.status(500).json({
          success: 'false',
          message: 'Error ocurred when checking database',
        })
      }

      //* return the error when no data in database match the requested data
      if (data.length === 0) {
        return res.status(404).json({
          success: 'false',
          message: 'Email or Password is incorrect',
        })
      }

      //* get the passphrase the was stored in the database
      const passphrase = data[0].passphrase

      //* split the encrypted data into smaller buffer called chunks
      const chunks = bufferHandle.splitBase64(encryptedData)

      //* decrypt each of chunk
      const decryptedChunks = chunks.map((chunk) =>
        decryption(chunk, privateKey, passphrase)
      )

      //* join all chunks into one buffer then convert it into utf-8 string
      const decryptedData = bufferHandle.join(decryptedChunks).toString('utf-8')

      console.log('Completed Decryption!')

      //* return the result
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
