package dev.alteration.x10.hookshot.jwt

import dev.alteration.x10.hookshot.crypto.Crypto
import TokenAlg.{HS256, HS512}
import dev.alteration.x10.hookshot.extensions.mapError
import dev.alteration.x10.hookshot.oidc.OIDCUserInfo
import veil.Veil
import upickle.default.*

import java.time.Instant
import java.util.logging.{Level, Logger}
import scala.util.{Failure, Success, Try}

object UserToken {
  private val logger = Logger.getLogger(this.getClass.getName)

  abstract class SessionValidationException(val msg: String)
      extends Throwable(msg) {
    override def getMessage: String = msg
  }
  case object InvalidFormat
      extends SessionValidationException("JWT not correctly formatted")

  case object Unparsable
      extends SessionValidationException("Could not parse JSON payload of JWT")

  case object Expired
      extends SessionValidationException("JWT is before iat or after exp")

  case object InvalidSignature
      extends SessionValidationException("JWT signature is not valid")

  /** The secret key used to sign UserSession JWTs. Set via the JWT_SECRET env
    * variable. Defaults to a random value.
    */
  private val secretKey: String =
    Veil
      .get("JWT_SECRET")
      .getOrElse {
        logger.log(Level.WARNING, "JWT_SECRET not set! Using random value")
        Crypto.generatePrivateKey()
      }

  /** The default algorithm used to sign UserSession JWTs. Set via the JWT_ALG
    * env variable. Defaults to [[HS256]]
    */
  private val jwtAlg: TokenAlg =
    Veil
      .get("JWT_ALG")
      .map(TokenAlg.valueOf)
      .getOrElse {
        logger.log(Level.WARNING, "JWT_ALG not set! Using HS256")
        TokenAlg.HS256
      }

  /** Creates a securely signed JWT token representing a user's session.
    * @param userInfo
    *   The OIDC user info retrieved from the pocket-id server *
    * @param tokenExpiry
    *   How long from now the token should be valid for, in seconds
    * @param dynamicClaims
    *   Any extra app-specific information encoded as json
    * @param secret
    *   The secret key to sign the JWT
    * @param alg
    *   The algorithm to use to sign the JWT
    * @return
    */
  def createToken(
      userInfo: OIDCUserInfo,
      tokenExpiry: Int,
      dynamicClaims: Option[ujson.Value],
      secret: String = secretKey,
      alg: TokenAlg = jwtAlg
  ): String = {
    val now       = Instant.now().getEpochSecond
    val claims    = UserSession(
      sub = userInfo.sub,
      exp = now + tokenExpiry,
      iat = now,
      userInfo = userInfo,
      dynamic = dynamicClaims
    )
    val headerJs  = Crypto.base64Encode(write(TokenHeader(alg, "JWT")))
    val payloadJs = Crypto.base64Encode(write(claims))
    val toSign    = headerJs + "." + payloadJs
    val signature = alg match {
      case HS256 => Crypto.hmac256(toSign, secret)
      case HS512 => Crypto.hmac512(toSign, secret)
    }
    toSign + "." + signature
  }

  private def extractParts(token: String): Try[(String, String, String)] =
    token match {
      case s"$h.$p.$s" => Success((h, p, s))
      case _           =>
        Failure(InvalidFormat)
    }

  private def decodeJson(
      header: String,
      payload: String
  ): Try[(TokenHeader, UserSession)] = Try {
    upickle.read[TokenHeader](Crypto.base64Decode(header)) ->
      upickle.read[UserSession](Crypto.base64Decode(payload))
  }.mapError(_ => Unparsable)

  private def validateSignature(
      header: TokenHeader,
      hp: String,
      secret: String,
      signature: String
  ): Try[Unit] = {
    header.alg match {
      case HS256 =>
        Try {
          Crypto.validateHmac256(
            hp,
            secret,
            signature
          )
        }
      case HS512 =>
        Try(
          Crypto.validateHmac512(
            hp,
            secret,
            signature
          )
        )
    }
  }.filter(_ == true)
    .map(_ => ())
    .mapError(_ => InvalidSignature)

  private def validateExpiration(session: UserSession): Try[Unit] = {
    if session.isValid then Success(()) else Failure(Expired)
  }

  /** Validates the signed JWT payload, and extracts the encoded [[UserSession]]
    * @param token
    *   The JWT
    * @param secret
    *   The shared secret to validate the signature
    * @return
    */
  def validateToken(
      token: String,
      secret: String = secretKey
  ): Try[UserSession] = {
    for {
      (h, p, s)         <- extractParts(token)
      (header, session) <- decodeJson(h, p)
      _                 <- validateSignature(header, s"$h.$p", secret, s)
      _                 <- validateExpiration(session)
    } yield session
  }

  /** Returns a tamper resistant token for the [[state]] parameter. Use with
    * [[validateSignedState()]]
    * @param state
    *   The payload to sign
    * @return
    */
  def signState(state: String): String =
    Crypto.timestampedTokenHmac256(state, secretKey)

  /** Verifies the [[signedState]] payload hasn't been tampered with, and was
    * created within an allotted timeframe
    * @param signedState
    *   The payload yo verify
    * @return
    */
  def validateSignedState(signedState: String): Option[String] =
    Crypto.validateTimestampedTokenHmac256(
      signedState,
      secretKey,
      5 * 60 * 1000
    ) // 5 minutes

}
