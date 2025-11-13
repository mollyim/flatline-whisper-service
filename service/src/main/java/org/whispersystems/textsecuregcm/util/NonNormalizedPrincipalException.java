/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util;

public class NonNormalizedPrincipalException extends Exception {

  private final String originalPrincipal;
  private final String normalizedPrincipal;

  public NonNormalizedPrincipalException(final String originalPrincipal, final String normalizedPrincipal) {
    this.originalPrincipal = originalPrincipal;
    this.normalizedPrincipal = normalizedPrincipal;
  }

  public String getOriginalPrincipal() {
    return originalPrincipal;
  }

  public String getNormalizedPrincipal() {
    return normalizedPrincipal;
  }
}
