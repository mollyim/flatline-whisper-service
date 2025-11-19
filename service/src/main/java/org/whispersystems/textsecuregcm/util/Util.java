/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.util;

import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
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

public class Util {

  private static final RandomGenerator RANDOM_GENERATOR = new Random();

  public static final Runnable NOOP = () -> {};

  // Use `CompletableFuture#thenApply(ASYNC_EMPTY_RESPONSE) to convert futures to
  // CompletableFuture<Response> instead of using NOOP to convert them to CompletableFuture<Void>
  // for jersey controllers; https://github.com/eclipse-ee4j/jersey/issues/3901 causes controllers
  // returning Void futures to behave differently than synchronous controllers returning void
  public static final Function<Object, Response> ASYNC_EMPTY_RESPONSE = ignored -> Response.noContent().build();

  /**
   * Checks that the given principal is a valid, normalized principal.
   *
   * @param principal the principal to check
   *
   * @throws InvalidPrincipalException if the given principal is not a valid principal at all
   * @throws NonNormalizedPrincipalException if the given principal is a valid principal, but isn't normalized
   */
  public static void requireNormalizedPrincipal(final String principal) throws InvalidPrincipalException, NonNormalizedPrincipalException {
    // FLT(uoemai): Principals cannot be null.
    if (principal == null) {
      throw new InvalidPrincipalException();
    }

    // FLT(uoemai): Principals can only contain ASCII characters from 0x20 to 0x7E.
    for (int i = 0; i < principal.length(); i++) {
      char c = principal.charAt(i);
      if (c < 0x20 || c > 0x7E) {
        throw new InvalidPrincipalException();
      }
    }

    // FLT(uoemai): Normalized principals should be trimmed of leading and trailing spaces.
    final String normalizedPrincipal = principal.trim();
    if (!principal.equals(normalizedPrincipal)) {
      throw new NonNormalizedPrincipalException(principal, normalizedPrincipal);
    }

    // FLT(uoemai): Principals cannot be longer than 2048 characters after trimming.
    if (principal.length() > 2048) {
      throw new InvalidPrincipalException();
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
  public static List<String> getAlternateForms(final String principal) { return List.of(principal); }

  /**
   * Returns the preferred form of a principal from a list of equivalents. Only use this when there is no other reason (such
   * as the form specifically provided by a user) to prefer a particular form and we want to reduce nondeterminism
   * In Flatline, this will only be relevant if and when operators are allowed to define such an equivalence.
   * Currently, in Flatline, no "equivalent" principals can be associated with the same ACI or PNI.
   *
   * @apiNote This method is intended to support principal format transitions in cases where we do not already have
   * multiple accounts registered with different forms of the same principal. As a result, this method does not cover all
   * possible cases of equivalent formats, but instead focuses on the cases where we can and choose to prevent multiple
   * accounts from using different formats of the same principal.
   *
   * @param principals a list of equivalent forms of a single principal
   *
   * @return a single preferred canonical form for the principal
   */
  public static Optional<String> getCanonicalPrincipal(List<String> principals) {
      return principals.stream().sorted().findFirst();
  }

  /**
   * If applicable, return the canonical form of the provided principal.
   * This could be relevant in cases where an identity provider changes the format used for the principal claim.
   * In Flatline, this will only be relevant if and when such a principal migration is made available to operators.
   *
   * @param principal the principal to canonicalize.
   * @return the canonical principal if applicable, otherwise the original principal.
   */
  public static String canonicalizePrincipal(final String principal) { return principal; }

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
