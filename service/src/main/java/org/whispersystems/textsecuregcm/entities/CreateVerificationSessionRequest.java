/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.whispersystems.textsecuregcm.util.Principal;

public record CreateVerificationSessionRequest(
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Identifier of the provider used for the principal verification")
    @NotBlank
    @JsonProperty
    String providerId,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Value provided by the client to be used in the PKCE challenge")
    @NotBlank
    @JsonProperty
    String codeChallenge,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Value provided by the client to verify authorization responses")
    @NotBlank
    @JsonProperty
    String state,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Location provided by the client to be redirected after authorization")
    @NotBlank
    @JsonProperty
    String redirectUri,

    @Valid
    @JsonUnwrapped
    UpdateVerificationSessionRequest updateVerificationSessionRequest) {
}
