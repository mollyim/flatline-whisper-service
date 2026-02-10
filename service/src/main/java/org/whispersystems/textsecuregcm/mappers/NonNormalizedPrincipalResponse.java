/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.mappers;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class NonNormalizedPrincipalResponse {

  private final String originalPrincipal;
  private final String normalizedPrincipal;

  @JsonCreator
  NonNormalizedPrincipalResponse(@JsonProperty("originalPrincipal") final String originalPrincipal,
                                 @JsonProperty("normalizedPrincipal") final String normalizedPrincipal) {

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
