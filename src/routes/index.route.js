// const channelRoute = require('./channel.route');
// const userRoute = require('./user.route');
const rsaRoute = require('./rsa.route')

function route(app) {
  // app.use('/channels', channelRoute);
  // app.use('/user', userRoute);
  app.use('/rsa', rsaRoute)
}

module.exports = route
