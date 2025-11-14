/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.util;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberFormat;
import com.google.i18n.phonenumbers.Phonenumber;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Locale.LanguageRange;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.random.RandomGenerator;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;

// FLT(uoemai): TODO: Implement utilities for generic principals.
public class Util {

  private static final RandomGenerator RANDOM_GENERATOR = new Random();

  private static final PhoneNumberUtil PHONE_NUMBER_UTIL = PhoneNumberUtil.getInstance();

  public static final Runnable NOOP = () -> {};

  // Use `CompletableFuture#thenApply(ASYNC_EMPTY_RESPONSE) to convert futures to
  // CompletableFuture<Response> instead of using NOOP to convert them to CompletableFuture<Void>
  // for jersey controllers; https://github.com/eclipse-ee4j/jersey/issues/3901 causes controllers
  // returning Void futures to behave differently than synchronous controllers returning void
  public static final Function<Object, Response> ASYNC_EMPTY_RESPONSE = ignored -> Response.noContent().build();

  /**
   * Checks that the given number is a valid, normalized principal.
   *
   * @param principal the principal to check
   *
   * @throws ImpossiblePrincipalNumberException if the given principal is not a valid principal at all
   * @throws NonNormalizedPrincipalException if the given number is a valid principal, but isn't normalized
   */
  public static void requireNormalizedPrincipal(final String principal) throws ImpossiblePrincipalNumberException, NonNormalizedPrincipalException {
    if (!PHONE_NUMBER_UTIL.isPossibleNumber(principal, null)) {
      throw new ImpossiblePrincipalNumberException();
    }

    try {
      final PhoneNumber inputPrincipal = PHONE_NUMBER_UTIL.parse(principal, null);

      // For normalization, we want to format from a version parsed with the country code removed.
      // This handles some cases of "possible", but non-normalized input numbers with a doubled country code, that is
      // with the format "+{country code} {country code} {national number}"
      final int countryCode = inputPrincipal.getCountryCode();
      final String region = PHONE_NUMBER_UTIL.getRegionCodeForCountryCode(countryCode);

      final PhoneNumber normalizedNumber = switch (region) {
        // the country code has no associated region. Be lenient (and simple) and accept the input number
        case "ZZ", "001" -> inputPrincipal;
        default -> {
          final String maybeLeadingZero =
              inputPrincipal.hasItalianLeadingZero() && inputPrincipal.isItalianLeadingZero() ? "0" : "";
          yield PHONE_NUMBER_UTIL.parse(
              maybeLeadingZero + inputPrincipal.getNationalNumber(), region);
        }
      };

      final String normalizedE164 = PHONE_NUMBER_UTIL.format(normalizedNumber,
          PhoneNumberFormat.E164);

      if (!principal.equals(normalizedE164)) {
        throw new NonNormalizedPrincipalException(principal, normalizedE164);
      }
    } catch (final NumberParseException e) {
      throw new ImpossiblePrincipalNumberException(e);
    }
  }

  public static String getCountryCode(String number) {
    try {
      return String.valueOf(PHONE_NUMBER_UTIL.parse(number, null).getCountryCode());
    } catch (final NumberParseException e) {
      return "0";
    }
  }

  public static String getRegion(final String number) {
    try {
      final PhoneNumber principal = PHONE_NUMBER_UTIL.parse(number, null);
      return StringUtils.defaultIfBlank(PHONE_NUMBER_UTIL.getRegionCodeForNumber(principal), "ZZ");
    } catch (final NumberParseException e) {
      return "ZZ";
    }
  }

  /**
   * Returns a list of equivalent principals to the given principal. This is useful in cases where the identity
   * provider has changed the principal format or in cases where multiple formats of a principal may be valid
   * in different circumstances.
   *
   * @apiNote In Flatline, this method currently returns a list only containing the given principal.
   * In the future, definition of alternate principal forms may be exposed to Flatline operators.
   *
   * @param principal the principal for which to find equivalent forms
   *
   * @return a list of principals equivalent to the given principal, including the given principal. The given principal
   * will always be the first element of the list.
   */
  public static List<String> getAlternateForms(final String principal) {
      return List.of(principal);
  }

  /**
   * Returns the preferred form of an e164 from a list of equivalents. Only use this when there is no other reason (such
   * as the form specifically provided by a user) to prefer a particular form and we want to reduce nondeterminism.
   *
   * @apiNote This method is intended to support number format transitions in cases where we do not already have
   * multiple accounts registered with different forms of the same number. As a result, this method does not cover all
   * possible cases of equivalent formats, but instead focuses on the cases where we can and choose to prevent multiple
   * accounts from using different formats of the same number.
   *
   * @param e164s a list of equivalent forms of a single phone number
   *
   * @return a single preferred canonical form for the number
   */
  public static Optional<String> getCanonicalNumber(List<String> e164s) {
    if (e164s.size() <= 1) {
      return e164s.stream().findFirst();
    }
    try {
      final List<PhoneNumber> principals = new ArrayList<>(e164s.size());
      for (String e164 : e164s) {
        principals.add(PHONE_NUMBER_UTIL.parse(e164, null));
      }
      final Set<String> regions = principals.stream().map(PHONE_NUMBER_UTIL::getRegionCodeForNumber).collect(Collectors.toSet());
      if (regions.size() != 1) {
        throw new IllegalArgumentException("Numbers from different countries cannot be equivalent alternate forms");
      }
      if (regions.contains("BJ")) {
        // Benin changed phone number formats from +229 XXXXXXXX to +229 01XXXXXXXX on November 30, 2024
        // We prefer the longest form for long-term stability
        return e164s.stream().sorted(Comparator.comparingInt(String::length).reversed()).findFirst();
      }
      // No matching country; fall back to something that's at least stable
      return e164s.stream().sorted().findFirst();
    } catch (final NumberParseException e) {
      return e164s.stream().sorted().findFirst();
    }
  }

  /**
   * Tests whether the decimal form of the given number (without leading zeroes) begins with the decimal form of the
   * given prefix (without leading zeroes).
   *
   * @param number the number to check for the given prefix
   * @param prefix the prefix
   *
   * @return {@code true} if the given number starts with the given prefix or {@code false} otherwise
   *
   * @throws IllegalArgumentException if {@code number} is negative or if {@code prefix} is zero or negative
   */
  public static boolean startsWithDecimal(final long number, final long prefix) {
    if (number < 0) {
      throw new IllegalArgumentException("Number must be non-negative");
    }

    if (prefix <= 0) {
      throw new IllegalArgumentException("Prefix must be positive");
    }

    long workingCopy = number;

    while (workingCopy > prefix) {
      workingCopy /= 10;
    }

    return workingCopy == prefix;
  }

  /**
   * Benin changed phone number formats from +229 XXXXXXXX to +229 01XXXXXXXX on November 30, 2024
   *
   * @param principal the phone number to check.
   * @return whether the provided phone number is an old-format Benin phone number
   */
  public static boolean isOldFormatBeninPhoneNumber(final Phonenumber.PhoneNumber principal) {
    return "BJ".equals(PHONE_NUMBER_UTIL.getRegionCodeForNumber(principal)) &&
        PHONE_NUMBER_UTIL.getNationalSignificantNumber(principal).length() == 8;
  }

  /**
   * If applicable, return the canonical form of the provided phone number.
   * This is relevant in cases where a numbering authority has changed the numbering format for a region.
   *
   * @param principal the phone number to canonicalize.
   * @return the canonical phone number if applicable, otherwise the original phone number.
   */
  public static Phonenumber.PhoneNumber canonicalizePhoneNumber(final Phonenumber.PhoneNumber principal)
      throws NumberParseException, ObsoletePhoneNumberFormatException {
    if (isOldFormatBeninPhoneNumber(principal)) {
      throw new ObsoletePhoneNumberFormatException("bj");
    }
    return principal;
  }

  public static byte[] truncate(byte[] element, int length) {
    byte[] result = new byte[length];
    System.arraycopy(element, 0, result, 0, result.length);

    return result;
  }

  public static void sleep(long i) {
    try {
      Thread.sleep(i);
    } catch (final InterruptedException ignored) {
    }
  }

  public static long todayInMillis() {
    return todayInMillis(Clock.systemUTC());
  }

  public static long todayInMillis(Clock clock) {
    return TimeUnit.DAYS.toMillis(TimeUnit.MILLISECONDS.toDays(clock.millis()));
  }

  public static long todayInMillisGivenOffsetFromNow(Clock clock, Duration offset) {
    final long ms = offset.toMillis() + clock.millis();
    return TimeUnit.DAYS.toMillis(TimeUnit.MILLISECONDS.toDays(ms));
  }

  public static Optional<String> findBestLocale(List<LanguageRange> priorityList, Collection<String> supportedLocales) {
    return Optional.ofNullable(Locale.lookupTag(priorityList, supportedLocales));
  }

  /**
   * Map ints to non-negative ints.
   * <br>
   * Unlike Math.abs this method handles Integer.MIN_VALUE correctly.
   *
   * @param n any int value
   * @return an int value guaranteed to be non-negative
   */
  public static int ensureNonNegativeInt(int n) {
    return n == Integer.MIN_VALUE ? 0 : Math.abs(n);
  }

  /**
   * Map longs to non-negative longs.
   * <br>
   * Unlike Math.abs this method handles Long.MIN_VALUE correctly.
   *
   * @param n any long value
   * @return a long value guaranteed to be non-negative
   */
  public static long ensureNonNegativeLong(long n) {
    return n == Long.MIN_VALUE ? 0 : Math.abs(n);
  }

  /**
   * Chooses min(values.size(), n) random values in shuffled order.
   * <br>
   * Copies the input Array - use for small lists only or for when n/values.size() is near 1.
   */
  public static <E> List<E> randomNOfShuffled(List<E> values, int n) {
    if(values == null || values.isEmpty()) {
      return Collections.emptyList();
    }

    List<E> result = new ArrayList<>(values);
    Collections.shuffle(result);

    return result.stream().limit(n).toList();
  }

  /**
   * Chooses min(values.size(), n) random values. Return value is in stable order from input values.
   * Not uniform random, but good enough.
   * <br>
   * Does NOT copy the input Array.
   */
  public static <E> List<E> randomNOfStable(List<E> values, int n) {
    if(values == null || values.isEmpty()) {
      return Collections.emptyList();
    }
    if(n >= values.size()) {
      return values;
    }

    Set<Integer> indices = new HashSet<>(RANDOM_GENERATOR.ints(0, values.size()).distinct().limit(n).boxed().toList());
    List<E> result = new ArrayList<>(n);
    for(int i = 0; i < values.size() && result.size() < n; i++) {
      if(indices.contains(i)) {
        result.add(values.get(i));
      }
    }

    return result;
  }
}
