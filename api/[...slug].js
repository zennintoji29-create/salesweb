const server = require('../server.js');

module.exports = async (req, res) => {
  return server.handler(req, res);
};
