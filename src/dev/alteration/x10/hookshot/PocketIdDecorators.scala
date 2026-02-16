package dev.alteration.x10.hookshot

import cask.{Redirect, Request, Response}
import cask.model.Response.Raw
import cask.router.Result
import extensions.*
import java.net.URLEncoder

object PocketIdDecorators {

  /** If there is no [[dev.alteration.x10.hookshot.jwt.UserSession]] present,
    * this decorator will automatically try to log the user in via redirect to
    * the login endpoint.
    */
  class autoAuthorize extends cask.RawDecorator {
    override def wrapFunction(ctx: Request, delegate: Delegate): Result[Raw] = {
      ctx.getUserSession match {
        case Some(claims) =>
          delegate(ctx, Map("session" -> claims))
        case None         =>
          val originalUrl = ctx.exchange.getRequestPath
          val queryString =
            Option(ctx.exchange.getQueryString).filter(_.nonEmpty)
          val fullUrl     = queryString.fold(originalUrl)(qs => s"$originalUrl?$qs")
          val redirectTo  = URLEncoder.encode(fullUrl, "UTF-8")
          cask.router.Result.Success(
            Redirect(s"/login?redirectTo=$redirectTo").copy(statusCode = 302)
          )
      }
    }

  }

  /** If there is no [[dev.alteration.x10.hookshot.jwt.UserSession]] present,
    * return a 401 Unauthorized
    */
  class authorized extends cask.RawDecorator {
    override def wrapFunction(
        ctx: Request,
        delegate: Delegate
    ): Result[Raw] = {
      ctx.getUserSession match {
        case Some(claims) =>
          delegate(ctx, Map("session" -> claims))
        case None         =>
          cask.router.Result.Success(
            Response("Unauthorized", statusCode = 401)
          )
      }
    }
  }

  /** Parses out an optional [[dev.alteration.x10.hookshot.jwt.UserSession]]
    * from the Request session cookie
    */
  class maybeAuthorized extends cask.RawDecorator {
    override def wrapFunction(
        ctx: Request,
        delegate: Delegate
    ): Result[Raw] = {
      delegate(ctx, Map("session" -> ctx.getUserSession))
    }
  }
}
