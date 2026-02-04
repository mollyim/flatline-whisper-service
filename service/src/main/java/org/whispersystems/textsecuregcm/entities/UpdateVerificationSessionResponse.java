/*
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import io.swagger.v3.oas.annotations.media.Schema;

public record UpdateVerificationSessionResponse(
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A URL-safe ID for the verification session")
    String id,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The principal that has been verified with the verification session")
    String principal,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Whether this session is verified")
    boolean verified) {

}
