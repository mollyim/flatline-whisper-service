/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.Objects;
import java.util.Optional;

/**
 * Constraint annotation that requires annotated entity
 * to hold (or return) a string value that is a valid, normalized principal.
 */
@Target({ FIELD, PARAMETER, METHOD })
@Retention(RUNTIME)
@Constraint(validatedBy = {
    Principal.Validator.class,
    Principal.OptionalValidator.class
})
@Documented
public @interface Principal {

  String message() default "value is not a valid principal";

  Class<?>[] groups() default { };

  Class<? extends Payload>[] payload() default { };

  class Validator implements ConstraintValidator<Principal, String> {

    @Override
    public boolean isValid(final String value, final ConstraintValidatorContext context) {
      if (Objects.isNull(value)) {
        return true;
      }
      try {
        Util.requireNormalizedPrincipal(value);
      } catch (final InvalidPrincipalException | NonNormalizedPrincipalException e) {
        return false;
      }
      return true;
    }
  }

  class OptionalValidator implements ConstraintValidator<Principal, Optional<String>> {

    @Override
    public boolean isValid(final Optional<String> value, final ConstraintValidatorContext context) {
        return value.map(s -> new Validator().isValid(s, context)).orElse(true);
    }
  }
}
