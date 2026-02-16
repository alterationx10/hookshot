package dev.alteration.x10.hookshot

import cask.*
import dev.alteration.x10.hookshot.jwt.{UserSession, UserToken}

import scala.util.*

package object extensions {

  extension [A](request: Request) {

    /** Helper method to extract and marshal a cookie value.
      * @param cookieName
      *   The name of the cookie
      * @param fn
      *   A function to marshal the cookie value to B
      * @tparam B
      *   The type to marshal
      * @return
      */
    def extractCookie[B](
        cookieName: String
    )(fn: Option[Cookie] => Option[B]): Option[B] = {
      fn(request.cookies.get(cookieName))
    }

    /** Extract a [[UserSession]] from a cookie names `session`.
      * @return
      */
    def getUserSession: Option[UserSession] =
      extractCookie("session") { c =>
        c.flatMap { d =>
          UserToken.validateToken(d.value).toOption
        }
      }

  }

  extension [A](t: Try[A]) {

    /**
     * Map a Failure to another Throwable
     * @param fn
     * @return
     */
    def mapError(fn: Throwable => Throwable): Try[A] = t match {
      case s @ Success(value) => s
      case Failure(e)         => Failure(fn(e))
    }
  }

}
