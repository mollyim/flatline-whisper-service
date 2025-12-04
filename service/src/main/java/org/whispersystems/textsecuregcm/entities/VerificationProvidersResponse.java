/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

public record VerificationProvidersResponse(
    @JsonProperty @Schema(description = "information about each verification provider") List<VerificationProvidersResponseItem> providers) {

  public VerificationProvidersResponse(List<VerificationProvidersResponseItem> providers) {
    this.providers = providers;
  }

  @VisibleForTesting
  public List<VerificationProvidersResponseItem> getProviders() {
    return providers;
  }

  @VisibleForTesting
  public VerificationProvidersResponseItem getProvider(int index) {
    return providers.get(index);
  }

}
