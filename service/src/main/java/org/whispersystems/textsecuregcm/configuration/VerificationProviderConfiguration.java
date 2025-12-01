/*
 * Copyright 2021 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import jakarta.ws.rs.DefaultValue;
import org.whispersystems.textsecuregcm.entities.BadgeSvg;
import org.whispersystems.textsecuregcm.util.ExactlySize;

public class VerificationProviderConfiguration {
  private final String name;
  private final String issuer;
  private final String authorizationEndpoint;
  private final String parEndpoint;
  private final String jwksUri;
  private final String audience;
  private final String principalClaim;
  private final String scopes;

  @JsonCreator
  public VerificationProviderConfiguration(
      @JsonProperty("name") final String name,
      @JsonProperty("authorizationEndpoint") final String authorizationEndpoint,
      @JsonProperty("parEndpoint") final String parEndpoint,
      @JsonProperty("jwksUri") final String jwksUri,
      @JsonProperty("issuer") final String issuer,
      @JsonProperty("audience") final String audience,
      @JsonProperty("principalClaim") final String principalClaim,
      @JsonProperty("scopes") final String scopes) {
    this.name = name;
    this.authorizationEndpoint = authorizationEndpoint;
    this.parEndpoint = parEndpoint;
    this.jwksUri = jwksUri;
    this.issuer = issuer;
    this.audience = audience;
    this.principalClaim = principalClaim;
    this.scopes = scopes;
  }

  @NotEmpty
  public String getName() {
    return name;
  }

  @NotEmpty
  public String getAuthorizationEndpoint() {
    return authorizationEndpoint;
  }

  @NotEmpty
  public String getParEndpoint() { return parEndpoint; }

  @NotEmpty
  public String getJwksUri() {
    return jwksUri;
  }

  @NotEmpty
  public String getIssuer() {
    return issuer;
  }

  @NotEmpty
  public String getAudience() {
    return audience;
  }

  @DefaultValue("sub")
  public String getPrincipalClaim() {
    return principalClaim;
  }

  @DefaultValue("openid email profile")
  public String getScopes() {
    return scopes;
  }
}
