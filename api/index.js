// =========================================================================
// TOKYO DRIFT — VERCEL SERVERLESS FUNCTION ENTRYPOINT
// Routes all /api/* and /uploads/* serverless traffic directly to server engine
// =========================================================================

const server = require('../server.js');

module.exports = async (req, res) => {
  return server.handler(req, res);
};
