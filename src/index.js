const express = require('express')
require('dotenv').config()
const app = express()
const route = require('./routes/index.route')
const bodyParser = require('body-parser')
const cors = require('cors')
const PORT = process.env.PORT || 5000

app.use(bodyParser.json())
app.use(express.json())
app.use(cors())

route(app)

// Initialize the client with your Supabase URL and anon key

//Chạy server ở cổng 3001
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
