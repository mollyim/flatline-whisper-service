/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class UtilTest {
  @ParameterizedTest
  @MethodSource
  void getAlternateForms(final String principal, final List<String> expectedAlternateForms) {
    assertEquals(expectedAlternateForms, Util.getAlternateForms(principal));
  }

  static List<Arguments> getAlternateForms() {
    final String examplePrincipal = "user.account@example.com";
    return List.of(Arguments.of(examplePrincipal, List.of(examplePrincipal)));
  }

  @Test
  void getCanonicalPrincipal() {
    final String principal1 = "user.account1@example.com";
    final String principal2 = "user.account2@example.com";

    assertEquals(Optional.of(principal1), Util.getCanonicalPrincipal(List.of(principal1)));
    assertEquals(Optional.of(principal1), Util.getCanonicalPrincipal(List.of(principal1, principal2)));
    assertEquals(Optional.empty(), Util.getCanonicalPrincipal(List.of()));
  }

  @ParameterizedTest
  @CsvSource({
      "0, 1, false",
      "123456789, 1, true",
      "123456789, 123, true",
      "123456789, 456, false",
  })
  void startsWithDecimal(final long number, final long prefix, final boolean expectStartsWithPrefix) {
    assertEquals(expectStartsWithPrefix, Util.startsWithDecimal(number, prefix));
  }
}
