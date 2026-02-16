package dev.alteration.x10.hookshot.jwt

import upickle.default.*

/**
 * Class to model the header of a JWT
 * @param alg
 * @param typ
 */
private case class TokenHeader(alg: TokenAlg, typ: String) derives ReadWriter
