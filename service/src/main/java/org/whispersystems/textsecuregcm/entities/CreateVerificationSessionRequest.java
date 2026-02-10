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

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The principal to be verified")
    @Principal
    @NotBlank
    @JsonProperty
    String principal,


    @Valid
    @JsonUnwrapped
    UpdateVerificationSessionRequest updateVerificationSessionRequest) {


}
