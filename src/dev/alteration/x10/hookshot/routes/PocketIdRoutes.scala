package dev.alteration.x10.hookshot.routes

import cask.router.Result
import cask.*
import dev.alteration.x10.hookshot.PocketIdDecorators.maybeAuthorized
import dev.alteration.x10.hookshot.jwt.{UserSession, UserToken}
import dev.alteration.x10.hookshot.oidc.PocketIdClient
import mustachio.{Mustachio, Stache}

import java.util.UUID
import scala.io.Source
import scala.util.*

class PocketIdRoutes extends cask.Routes {

  @maybeAuthorized
  @get("/login")
  def login(
      redirectTo: Option[String] = None
  )(session: Option[UserSession]): Response[String] = {
    val redirect = session match {
      case Some(_) => "/"
      case None    =>
        val state = UserToken.signState(redirectTo.getOrElse("/"))
        PocketIdClient.buildAuthorizationUrl(state)
    }
    Response("", 302, Seq("Location" -> redirect))
  }

  @get("/logout")
  def logout(): Response[String] = {
    Response(
      "",
      302,
      Seq(
        "Location"   -> "/",
        "Set-Cookie" -> "session=; Path=/; HttpOnly; Max-Age=0"
      )
    )
  }

  @get("/auth/callback")
  def authCallback(
      code: String,
      state: String,
      iss: String
  ): Response[String] = {
    val redirectUrl = UserToken.validateSignedState(state)
    if redirectUrl.isEmpty then return Response("VERBOTEN!", 403)

    if !PocketIdClient.pocketIdEndpoint.equals(iss) then
      return Response("VERBOTEN!", 403)

    PocketIdClient.exchangeCodeForTokens(code) match {
      case Success(tokenResponse) =>
        PocketIdClient.getUserInfo(tokenResponse.access_token) match {
          case Success(userInfo) =>
            val jwt = UserToken.createToken(
              userInfo,
              3600 * 24,
              Some(
                upickle.writeJs(userInfo)
              )
            )
            cask
              .Redirect(redirectUrl.get)
              .copy(
                statusCode = 302,
                cookies = Seq(Cookie("session", jwt, path = "/"))
              )
          case Failure(e)        =>
            Response(s"Failed to get user info: ${e.getMessage}", 500)
        }
      case Failure(e)             =>
        Response(s"Failed to get user info: ${e.getMessage}", 500)
    }

  }

  @maybeAuthorized
  @get("/register")
  def register()(session: Option[UserSession]): Response[String] = {
    session match {
      case Some(_) => Response("", 302, Seq("Location" -> "/"))
      case None    =>
        val csrfToken = UserToken.signState(UUID.randomUUID().toString)
        val stache    = Stache.obj("csrfToken" -> Stache.str(csrfToken))

        val html = scala.util.Using.resource(
          Source.fromResource("templates/register.html.mustache")
        ) { buff =>
          val template = buff.mkString
          Mustachio.render(template, stache)
        }

        Response(html, headers = Seq("Content-Type" -> "text/html"))
    }
  }

  @postForm("/register")
  def registerSubmit(consent: String, csrfToken: String): Response[String] = {
    if (UserToken.validateSignedState(csrfToken).isEmpty) {
      return Response("VERBOTEN!", 403)
    }
    if (consent != "true") {
      return Response("You must accept the terms to register.", 400)
    }
    PocketIdClient.createSignupToken() match {
      case Success(signupToken) =>
        val registerUrl = PocketIdClient.buildTokenLink(signupToken.token)
        Response("", 302, Seq("Location" -> registerUrl))
      case Failure(e)           =>
        Response(s"Failed to create registration: ${e.getMessage}", 500)
    }
  }

  initialize()
}
