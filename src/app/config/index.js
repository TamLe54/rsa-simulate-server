const { createClient } = require('@supabase/supabase-js')
require('dotenv').config()

// Initialize the client with your Supabase URL and anon key
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANNON_KEY
)

module.exports = supabase
