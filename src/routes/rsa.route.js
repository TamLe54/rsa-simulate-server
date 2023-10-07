const express = require('express')
const router = express.Router()
const rsaController = require('../app/controllers/rsa.controller')

router.post('/key-generate', rsaController.generateKey)
router.post('/encrypt', rsaController.encrypt)
router.post('/decrypt', rsaController.decrypt)

module.exports = router
