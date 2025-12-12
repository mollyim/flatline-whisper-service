/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import javax.annotation.Nullable;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import org.whispersystems.textsecuregcm.push.PushNotification;

public record UpdateVerificationSessionRequest(
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Authorization code used to obtain a token from the verification provider")
    @NotBlank
    @JsonProperty
    String code,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Value provided by the client as the PKCE proof")
    @NotBlank
    @JsonProperty
    String codeVerifier,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Value provided by the client to verify authorization responses")
    @NotBlank
    @JsonProperty
    String state) {
}
