const rsaRoute = require('./rsa.route')

function route(app) {
  app.use('/rsa', rsaRoute)
}

module.exports = route
