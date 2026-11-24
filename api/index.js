/**
 * Vercel Serverless Function Entry Point
 * Bridges Express app to Vercel's serverless edge/lambda infrastructure
 */

const app = require('../server');

module.exports = app;
