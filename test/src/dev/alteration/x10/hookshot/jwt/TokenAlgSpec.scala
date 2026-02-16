package dev.alteration.x10.hookshot.jwt

import munit.FunSuite

class TokenAlgSpec extends FunSuite {

  test("Encodes as a JSON String") {

    assertEquals(
      upickle.write(TokenAlg.HS256),
      upickle.write(ujson.Str("HS256"))
    )

    assertEquals(
      upickle.write(TokenAlg.HS512),
      upickle.write(ujson.Str("HS512"))
    )

  }

  test("Decodes from a JSON String") {
    assertEquals(
      upickle.default.read[TokenAlg](ujson.Str("HS256")),
      TokenAlg.HS256
    )

    assertEquals(
      upickle.default.read[TokenAlg](ujson.Str("HS512")),
      TokenAlg.HS512
    )

  }

}
