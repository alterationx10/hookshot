package dev.alteration.x10.hookshot.jwt

import dev.alteration.x10.hookshot.oidc.OIDCUserInfo
import upickle.default.*

import java.time.Instant

/** A model of the data stored in a cookie for a users session
  * @param sub
  *   The user's OIDC user id
  * @param exp
  *   The time the session expires
  * @param iat
  *   The time the sessions was issued
  * @param userInfo
  *   The OIDC user info payload returned from the pocket-id instance
  * @param dynamic
  *   A dynamic field, to store/support app-specific information.
  */
final case class UserSession(
    sub: String,
    exp: Long,
    iat: Long,
    userInfo: OIDCUserInfo,
    dynamic: Option[ujson.Value]
) derives ReadWriter

object UserSession {

  extension (c: UserSession) {

    /** Checks if the current time is after iat and before exp
      * @return
      */
    def isValid: Boolean = {
      val now = Instant.now().getEpochSecond
      c.iat <= now && c.exp > now
    }

  }

}
