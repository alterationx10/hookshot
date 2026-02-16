package dev.alteration.x10.hookshot.oidc

import dev.alteration.x10.hookshot.crypto.Crypto
import upickle.default.*
import veil.Veil

import java.net.URLEncoder
import scala.util.Try

/** Response for a
  * @param access_token
  * @param token_type
  * @param expires_in
  * @param refresh_token
  * @param id_token
  * @param scope
  */
private case class TokenResponse(
    access_token: String,
    token_type: String,
    expires_in: Option[Int] = None,
    refresh_token: Option[String] = None,
    id_token: Option[String] = None,
    scope: Option[String] = None
) derives ReadWriter

case class SignupToken(
    id: String,
    token: String
) derives ReadWriter

case class OIDCUserInfo(
    sub: String,
    email: Option[String] = None,
    name: Option[String] = None,
    given_name: Option[String] = None,
    family_name: Option[String] = None,
    picture: Option[String] = None,
    email_verified: Option[Boolean] = None,
    groups: Option[Set[String]] = None
) derives ReadWriter

object PocketIdClient {

  /** Root URI for Pocket-ID instance. Defaults to http://localhost:1411
    */
  private[x10] val pocketIdEndpoint: String =
    Veil
      .get("POCKET_ID_ENDPOINT")
      .getOrElse("http://localhost:1411")

  /** The OIDC Client ID for this application.
    */
  private val clientId: String =
    Veil
      .get("OIDC_CLIENT_ID")
      .getOrElse(throw new IllegalStateException("OIDC_CLIENT_ID not set"))

  /** The OIDC Client Secret for this application
    */
  private val clientSecret: String =
    Veil
      .get("OIDC_CLIENT_SECRET")
      .getOrElse(throw new IllegalStateException("OIDC_CLIENT_SECRET not set"))

  /** The re-direct url when building the authorization request
    */
  private val redirectUri: String =
    Veil
      .get("OIDC_REDIRECT_URI")
      .getOrElse(throw new IllegalStateException("OIDC_REDIRECT_URI not set"))

  /** The API key for the Pocket Id instance. Needed to generate signup tokens.
    */
  private val apiKey: String =
    Veil
      .get("POCKET_ID_API_KEY")
      .getOrElse(throw new IllegalStateException("POCKET_ID_API_KEY not set"))

  /** The URL for authorization via Code flow with Pocket ID
    * @param state
    * @return
    */
  def buildAuthorizationUrl(state: String): String = {
    val queryString = Map(
      "response_type" -> "code",
      "client_id"     -> clientId,
      "redirect_uri"  -> redirectUri,
      "scope"         -> "openid email profile groups",
      "state"         -> state
    ).map { case (k, v) =>
      s"$k=${URLEncoder.encode(v, "UTF-8")}"
    }.mkString("&")

    s"$pocketIdEndpoint/authorize?$queryString"

  }

  /** Exchange an auth Code for a Token from Pocket ID
    * @param code
    * @return
    */
  def exchangeCodeForTokens(code: String): Try[TokenResponse] = Try {
    // Create Basic Auth header
    val credentials        = s"$clientId:$clientSecret"
    val encodedCredentials = {
      Crypto.base64Encode(credentials.getBytes("UTF-8"))
    }

    val params = Map(
      "grant_type"   -> "authorization_code",
      "code"         -> code,
      "redirect_uri" -> redirectUri
    )

    val response = requests.post(
      s"$pocketIdEndpoint/api/oidc/token",
      headers = Map(
        "Authorization" -> s"Basic $encodedCredentials",
        "Content-Type"  -> "application/x-www-form-urlencoded"
      ),
      data = params
    )

    read[TokenResponse](response.text())
  }

  /** Request the user info for a given accessToken
    * @param accessToken
    * @return
    */
  def getUserInfo(accessToken: String): Try[OIDCUserInfo] = Try {
    val response = requests.get(
      s"$pocketIdEndpoint/api/oidc/userinfo",
      headers = Map("Authorization" -> s"Bearer $accessToken")
    )
    val resp     = response.text()
    read[OIDCUserInfo](response.text())
  }

  /** Generates a code a user can use to register with the Pocket ID instance.
    * @param ttl
    *   defaults to 5m
    * @param usageLimit
    *   defaults to 1
    * @param userGroupIds
    *   defaults to Seq.empty
    * @return
    */
  def createSignupToken(
      ttl: String = "5m",
      usageLimit: Int = 1,
      userGroupIds: Seq[String] = Seq.empty
  ): Try[SignupToken] = Try {
    val body = ujson.Obj(
      "ttl"          -> ttl,
      "usageLimit"   -> usageLimit,
      "userGroupIds" -> userGroupIds
    )

    val response = requests.post(
      s"$pocketIdEndpoint/api/signup-tokens",
      headers = Map(
        "X-API-KEY"    -> apiKey,
        "Content-Type" -> "application/json"
      ),
      data = ujson.write(body)
    )

    read[SignupToken](response.text())
  }

  /** Builds a URL for pocket ID that uses a code, and goes directly to a
    * registration UI
    * @param token
    * @return
    */
  def buildTokenLink(token: String): String =
    s"$pocketIdEndpoint/signup?token=$token"

  def refreshAccessToken(refreshToken: String): Try[TokenResponse] = Try {
    val credentials        = s"$clientId:$clientSecret"
    val encodedCredentials = Crypto.base64Encode(credentials)

    val params = Map(
      "grant_type"    -> "refresh_token",
      "refresh_token" -> refreshToken
    )

    val response = requests.post(
      s"$pocketIdEndpoint/api/oidc/token",
      headers = Map(
        "Authorization" -> s"Basic $encodedCredentials",
        "Content-Type"  -> "application/x-www-form-urlencoded"
      ),
      data = params
    )

    read[TokenResponse](response.text())
  }

}
