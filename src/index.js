const express = require('express')
require('dotenv').config()
const app = express()
const route = require('./routes/index.route')
const bodyParser = require('body-parser')
const cors = require('cors')
const PORT = process.env.PORT || 5000
const supabase = require('./app/config/index')

app.use(bodyParser.json())
app.use(express.json())
app.use(cors())

route(app)

// check database
supabase.from('RSA_Account').select('*').then(()=>{
  console.log("Connect to database successfully")
}).catch((error)=>{
  console.log("There is problem when connecting to database", error)
})

//run server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
