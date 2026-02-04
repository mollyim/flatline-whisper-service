/*
 * Copyright 2021 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.ws.rs.DefaultValue;
import org.checkerframework.common.value.qual.MatchesRegex;

public class VerificationProviderConfiguration {
  private final String id;
  private final String name;
  private final String issuer;
  private final String authorizationEndpoint;
  private final String tokenEndpoint;
  private final String parEndpoint;
  private final String jwksUri;
  private final String scopes;
  private final String principalClaim;
  private final String clientId;

  @JsonCreator
  public VerificationProviderConfiguration(
      // FLT(uoemai): For storage in DynamoDB, the provider identifier must not contain colons.
      //              For simplicity a minimal alphanumeric plus dash/underscore pattern is enforced.
      @MatchesRegex("[a-zA-Z0-9_-]+") @JsonProperty("id") final String id,
      @JsonProperty("name") final String name,
      @JsonProperty("issuer") final String issuer,
      @JsonProperty("authorizationEndpoint") final String authorizationEndpoint,
      @JsonProperty("tokenEndpoint") final String tokenEndpoint,
      @JsonProperty("parEndpoint") final String parEndpoint,
      @JsonProperty("jwksUri") final String jwksUri,
      @JsonProperty("clientId") final String clientId,
      @JsonProperty("scopes") final String scopes,
      @JsonProperty("principalClaim") final String principalClaim) {
    this.id = id;
    this.name = name;
    this.issuer = issuer;
    this.authorizationEndpoint = authorizationEndpoint;
    this.tokenEndpoint = tokenEndpoint;
    this.parEndpoint = parEndpoint;
    this.jwksUri = jwksUri;
    this.clientId = clientId;
    this.scopes = scopes;
    this.principalClaim = principalClaim;
  }

  @Valid
  @NotEmpty
  public String getId() {
    return id;
  }

  @NotEmpty
  public String getName() {
    return name;
  }

  @NotEmpty
  public String getIssuer() {
    return issuer;
  }

  @NotEmpty
  public String getAuthorizationEndpoint() {
    return authorizationEndpoint;
  }

  @NotEmpty
  public String getTokenEndpoint() {
    return tokenEndpoint;
  }

  @NotEmpty
  public String getParEndpoint() {
    return parEndpoint;
  }

  @NotEmpty
  public String getJwksUri() {
    return jwksUri;
  }

  @NotEmpty
  public String getClientId() {
    return clientId;
  }

  @DefaultValue("openid email profile")
  public String getScopes() {
    return scopes;
  }

  @DefaultValue("sub")
  public String getPrincipalClaim() {
    return principalClaim;
  }
}
