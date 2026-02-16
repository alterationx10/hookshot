package dev.alteration.x10.hookshot

import cask.*
import cask.router.Result
import dev.alteration.x10.hookshot.routes.PocketIdRoutes
import PocketIdDecorators.*
import dev.alteration.x10.hookshot.jwt.UserSession

import scala.util.*

object App extends MainRoutes {

  @get("/")
  def index(): Response[String] = {
    Response(
      """<html>
        |<head><title>Hookshot OIDC Demo</title></head>
        |<body>
        |  <h1>Hookshot OIDC Demo</h1>
        |  <p><a href="/login">Login with OIDC</a></p>
        |  <p><a href="/me">View Profile (requires login)</a></p>
        |</body>
        |</html>""".stripMargin,
      headers = Seq("Content-Type" -> "text/html")
    )
  }

  @autoAuthorize
  @get("/me")
  def me()(session: UserSession): Response[String] = {
    Response(
      s"""<html>
         |<head><title>Profile</title></head>
         |<body>
         |  <h1>Your Profile</h1>
         |  <p><strong>User ID:</strong> ${session.sub}</p>
         |  <p>${upickle.default.write(session.dynamic, indent = 4)}</p>
         |  <p><a href="/logout">Logout</a></p>
         |</body>
         |</html>""".stripMargin,
      headers = Seq("Content-Type" -> "text/html")
    )
  }

  println(s"Running at http://localhost:8080")
  initialize()

  override def allRoutes: Seq[Routes] = {
    PocketIdRoutes() +: super.allRoutes
  }

}
