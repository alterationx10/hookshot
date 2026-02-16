package dev.alteration.x10.hookshot.jwt

import upickle.default.*

/**
 * Supported hash algorithms for JWT signing
 */
enum TokenAlg derives ReadWriter {
  case HS256, HS512
}
