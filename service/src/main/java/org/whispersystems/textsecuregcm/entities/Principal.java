package org.whispersystems.textsecuregcm.entities;

import org.whispersystems.textsecuregcm.util.InvalidPrincipalException;
import org.whispersystems.textsecuregcm.util.NonNormalizedPrincipalException;
import org.whispersystems.textsecuregcm.util.Util;

public final class Principal {
  private final String value;

  public Principal(String value) throws NonNormalizedPrincipalException, InvalidPrincipalException {
    Util.requireNormalizedPrincipal(value);
    this.value = value;
  }

  public static Principal parse(String value) throws InvalidPrincipalException {
    // FLT(uoemai): For principals, parsing just means normalizing the principal string.
    //              Principal normalization currently involves trimming leading and trailing spaces.
    value = value.trim();
    try {
      return new Principal(value);
    } catch (NonNormalizedPrincipalException e) {
      // FLT(uoemai): At this point, the constructor should only fail if the principal is invalid.
      throw new InvalidPrincipalException(e);
    }
  }

  public String getValue() {
    return value;
  }

  @Override
  public String toString() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof final Principal that)) return false;
    return value.equals(that.value);
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }
}

