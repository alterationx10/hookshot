package dev.alteration.x10.hookshot.jwt

import dev.alteration.x10.hookshot.oidc.OIDCUserInfo
import munit.FunSuite

class UserTokenSpec extends FunSuite {

  val userInfo = OIDCUserInfo(sub = "abc123")

  test("create/validates HS256") {
    val token =
      UserToken.createToken(userInfo, 3600, None, alg = TokenAlg.HS256)
    assert(UserToken.validateToken(token).isSuccess)
  }

  test("create/validates HS512") {
    val token2 =
      UserToken.createToken(userInfo, 3600, None, alg = TokenAlg.HS512)
    assert(UserToken.validateToken(token2).isSuccess)

  }

}
