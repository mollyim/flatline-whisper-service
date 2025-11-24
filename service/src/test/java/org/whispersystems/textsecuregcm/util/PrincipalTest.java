/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

public class PrincipalTest {

  private static final Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

  private static final String PRINCIPAL_VALID = "valid.principal@example.com";

  private static final String PRINCIPAL_INVALID = "invalid.principal.¥€Š";

  private static final String EMPTY = "";

  @SuppressWarnings("FieldCanBeLocal")
  private static class Data {

    @Principal
    private final String principal;

    @Principal
    private final Optional<String> optionalPrincipal;

    private Data(final String principal, final Optional<String> optionalPrincipal) {
      this.principal = principal;
      this.optionalPrincipal = optionalPrincipal;
    }
  }

  private static class Methods {

    public void foo(@Principal final String principal, @Principal final Optional<String> optionalPrincipal) {
      // noop
    }

    @Principal
    public String bar() {
      return "nevermind";
    }

    @Principal
    public Optional<String> barOptionalString() {
      return Optional.of("nevermind");
    }
  }

  private record Rec(@Principal String principal, @Principal Optional<String> optionalPrincipal) {
  }

  @Test
  public void testRecord() {
    checkNoViolations(new Rec(PRINCIPAL_VALID, Optional.of(PRINCIPAL_VALID)));
    checkHasViolations(new Rec(PRINCIPAL_INVALID, Optional.of(PRINCIPAL_INVALID)));
    checkHasViolations(new Rec(EMPTY, Optional.of(EMPTY)));
  }

  @Test
  public void testClassField() {
    checkNoViolations(new Data(PRINCIPAL_VALID, Optional.of(PRINCIPAL_VALID)));
    checkHasViolations(new Data(PRINCIPAL_INVALID, Optional.of(PRINCIPAL_INVALID)));
    checkHasViolations(new Data(EMPTY, Optional.of(EMPTY)));
  }

  @Test
  public void testParameters() throws Exception {
    final Methods m = new Methods();
    final Method foo = Methods.class.getMethod("foo", String.class, Optional.class);

    final Set<ConstraintViolation<Methods>> violations1 =
        VALIDATOR.forExecutables().validateParameters(m, foo, new Object[] {
            PRINCIPAL_VALID, Optional.of(PRINCIPAL_VALID)});
    final Set<ConstraintViolation<Methods>> violations2 =
        VALIDATOR.forExecutables().validateParameters(m, foo, new Object[] {
            PRINCIPAL_INVALID, Optional.of(PRINCIPAL_INVALID)});
    final Set<ConstraintViolation<Methods>> violations3 =
        VALIDATOR.forExecutables().validateParameters(m, foo, new Object[] {EMPTY, Optional.of(EMPTY)});

    assertTrue(violations1.isEmpty());
    assertFalse(violations2.isEmpty());
    assertFalse(violations3.isEmpty());
  }

  @Test
  public void testReturnValue() throws Exception {
    final Methods m = new Methods();
    final Method bar = Methods.class.getMethod("bar");

    final Set<ConstraintViolation<Methods>> violations1 =
        VALIDATOR.forExecutables().validateReturnValue(m, bar, PRINCIPAL_VALID);
    final Set<ConstraintViolation<Methods>> violations2 =
        VALIDATOR.forExecutables().validateReturnValue(m, bar, PRINCIPAL_INVALID);
    final Set<ConstraintViolation<Methods>> violations3 =
        VALIDATOR.forExecutables().validateReturnValue(m, bar, EMPTY);

    assertTrue(violations1.isEmpty());
    assertFalse(violations2.isEmpty());
    assertFalse(violations3.isEmpty());
  }

  @Test
  public void testOptionalReturnValue() throws Exception {
    final Methods m = new Methods();
    final Method bar = Methods.class.getMethod("barOptionalString");

    final Set<ConstraintViolation<Methods>> violations1 =
        VALIDATOR.forExecutables().validateReturnValue(m, bar, Optional.of(PRINCIPAL_VALID));
    final Set<ConstraintViolation<Methods>> violations2 =
        VALIDATOR.forExecutables().validateReturnValue(m, bar, Optional.of(PRINCIPAL_INVALID));
    final Set<ConstraintViolation<Methods>> violations3 =
        VALIDATOR.forExecutables().validateReturnValue(m, bar, Optional.of(EMPTY));

    assertTrue(violations1.isEmpty());
    assertFalse(violations2.isEmpty());
    assertFalse(violations3.isEmpty());
  }

  private static <T> void checkNoViolations(final T object) {
    final Set<ConstraintViolation<T>> violations = VALIDATOR.validate(object);
    assertTrue(violations.isEmpty());
  }

  private static <T> void checkHasViolations(final T object) {
    final Set<ConstraintViolation<T>> violations = VALIDATOR.validate(object);
    assertFalse(violations.isEmpty());
  }
}
