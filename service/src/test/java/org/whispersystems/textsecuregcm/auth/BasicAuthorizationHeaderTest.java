/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.whispersystems.textsecuregcm.storage.Device;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class BasicAuthorizationHeaderTest {

  @Test
  void fromString() throws InvalidAuthorizationHeaderException {
    {
      final BasicAuthorizationHeader header =
          BasicAuthorizationHeader.fromString("Basic YWxhZGRpbjpvcGVuc2VzYW1l");

      assertEquals("aladdin", header.getUsername());
      assertEquals("opensesame", header.getPassword());
      assertEquals(Device.PRIMARY_ID, header.getDeviceId());
    }

    {
      final BasicAuthorizationHeader header = BasicAuthorizationHeader.fromString("Basic " +
          Base64.getEncoder().encodeToString(("username" + "\0" + "7:password").getBytes(StandardCharsets.UTF_8)));

      assertEquals("username", header.getUsername());
      assertEquals("password", header.getPassword());
      assertEquals(7, header.getDeviceId());
    }

    // FLT(uoemai): Test that principals can safely contain colons and periods.
    //              Before Flatline, principals were assumed to be phone numbers in E164 format.
    {
      final BasicAuthorizationHeader header = BasicAuthorizationHeader.fromString("Basic " +
          Base64.getEncoder().encodeToString(("arn:based:principal/test.example" + "\0" + "7:password").getBytes(StandardCharsets.UTF_8)));

      assertEquals("arn:based:principal/test.example", header.getUsername());
      assertEquals("password", header.getPassword());
      assertEquals(7, header.getDeviceId());
    }
  }

  @ParameterizedTest
  @MethodSource
  void fromStringMalformed(final String header) {
    assertThrows(InvalidAuthorizationHeaderException.class,
        () -> BasicAuthorizationHeader.fromString(header));
  }

  private static Stream<String> fromStringMalformed() {
    return Stream.of(
        null,
        "",
        "   ",
        "Obviously not a valid authorization header",
        "Digest YWxhZGRpbjpvcGVuc2VzYW1l",
        "Basic",
        "Basic ",
        "Basic &&&&&&",
        "Basic " + Base64.getEncoder().encodeToString("".getBytes(StandardCharsets.UTF_8)),
        "Basic " + Base64.getEncoder().encodeToString(":".getBytes(StandardCharsets.UTF_8)),
        "Basic " + Base64.getEncoder().encodeToString("test".getBytes(StandardCharsets.UTF_8)),
        "Basic " + Base64.getEncoder().encodeToString("test\0".getBytes(StandardCharsets.UTF_8)),
        "Basic " + Base64.getEncoder().encodeToString("test\0:".getBytes(StandardCharsets.UTF_8)),
        "Basic " + Base64.getEncoder().encodeToString("test\0:password".getBytes(StandardCharsets.UTF_8)),
        "Basic " + Base64.getEncoder().encodeToString(":password".getBytes(StandardCharsets.UTF_8)));
  }
}
