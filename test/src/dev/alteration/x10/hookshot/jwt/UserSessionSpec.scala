package dev.alteration.x10.hookshot.jwt

import dev.alteration.x10.hookshot.oidc.OIDCUserInfo
import munit.FunSuite

import java.time.*

class UserSessionSpec extends FunSuite {

  val userInfo = OIDCUserInfo(sub = "abc123")

  test("is valid between iat and exp") {
    val now    = Instant.now()
    val claims = UserSession(
      "",
      now.plusSeconds(30).getEpochSecond,
      now.minusSeconds(30).getEpochSecond,
      userInfo,
      None
    )
    assert(claims.isValid)
  }

  test("is not valid before iat") {
    val now    = Instant.now()
    val claims = UserSession(
      "",
      now.plusSeconds(30).getEpochSecond,
      now.plusSeconds(1).getEpochSecond,
      userInfo,
      None
    )
    assert(!claims.isValid)
  }

  test("is not valid after exp") {
    val now    = Instant.now()
    val claims = UserSession(
      "",
      now.minusSeconds(1).getEpochSecond,
      now.minusSeconds(30).getEpochSecond,
      userInfo,
      None
    )
    assert(!claims.isValid)
  }

}
