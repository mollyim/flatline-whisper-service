/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.ws.rs.DefaultValue;

public class VerificationProvidersResponseItem {
  @JsonProperty
  @Schema(description="the ID of the verification provider")
  private String id;

  @JsonProperty
  @Schema(description="the display name of the verification provider")
  private String name;

  @JsonProperty
  @Schema(description="the issuer location of the verification provider")
  private String issuer;

  @JsonProperty
  @Schema(description="the authorization endpoint of the verification provider")
  private String authorizationEndpoint;

  @JsonProperty
  @Schema(description="the claim from the verification provider to use as the account principal")
  private String principalClaim;

  public VerificationProvidersResponseItem() {}

  public VerificationProvidersResponseItem(
      final String id,
      final String name,
      final String issuer,
      final String authorizationEndpoint,
      final String principalClaim) {
    this.id = id;
    this.name = name;
    this.issuer = issuer;
    this.authorizationEndpoint = authorizationEndpoint;
    this.principalClaim = principalClaim;
  }
  @VisibleForTesting
  public String getId() {
    return id;
  }

  @VisibleForTesting
  public String getName() {
    return name;
  }

  @VisibleForTesting
  public String getIssuer() {
    return issuer;
  }

  @VisibleForTesting
  public String getAuthorizationEndpoint() {
    return authorizationEndpoint;
  }

  @VisibleForTesting
  public String getPrincipalClaim() {
    return principalClaim;
  }

}
