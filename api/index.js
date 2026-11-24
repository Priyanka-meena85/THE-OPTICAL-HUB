/**
 * Vercel Serverless Function Entry Point
 * Bridges Express app to Vercel's serverless edge/lambda infrastructure
 */

const app = require('../server');

module.exports = (req, res) => {
  return app(req, res);
};
