/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration.dynamic;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.util.Collections;
import java.util.Set;

public class DynamicPrincipalExperimentEnrollmentConfiguration {

  @JsonProperty
  @Valid
  private Set<String> enrolledPrincipals = Collections.emptySet();

  @JsonProperty
  @Valid
  private Set<String> excludedPrincipals = Collections.emptySet();

  @JsonProperty
  @Valid
  @Min(0)
  @Max(100)
  private int enrollmentPercentage = 0;

  public Set<String> getEnrolledPrincipals() {
    return enrolledPrincipals;
  }

  public Set<String> getExcludedPrincipals() {
    return excludedPrincipals;
  }

  public int getEnrollmentPercentage() {
    return enrollmentPercentage;
  }
}
