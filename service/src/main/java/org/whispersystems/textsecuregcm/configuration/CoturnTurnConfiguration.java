/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.time.Duration;
import java.util.List;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/**
 * Configuration properties for Coturn TURN integration.
 *
 * @param secret the shared secret used to generate temporary TURN tokens for Coturn
 * @param credentialTtl the lifetime of TURN tokens generated for Coturn
 * @param clientCredentialTtl the time clients may cache a TURN token; must be less than or equal to {@link #credentialTtl}
 * @param urls a collection of TURN URLs to include verbatim in responses to clients
 * @param urlsWithIps a collection of {@link String#format(String, Object...)} patterns to be populated with resolved IP
 *                    addresses for {@link #hostname} in responses to clients; each pattern must include a single
 *                    {@code %s} placeholder for the IP address
 * @param hostname the hostname to resolve to IP addresses for use with {@link #urlsWithIps}; also transmitted to
 *                 clients for use as an SNI when connecting to pre-resolved hosts
 */
public record CoturnTurnConfiguration(@NotNull SecretString secret,
                                      @NotNull Duration credentialTtl,
                                      @NotNull Duration clientCredentialTtl,
                                      @NotNull @NotEmpty @Valid List<@NotBlank String> urls,
                                      @NotNull @NotEmpty @Valid List<@NotBlank String> urlsWithIps,
                                      @NotBlank String hostname) {

  @AssertTrue
  @Schema(hidden = true)
  public boolean isClientTtlShorterThanRequestedTtl() {
    return clientCredentialTtl.compareTo(credentialTtl) <= 0;
  }
}
