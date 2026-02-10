/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.mappers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.ext.ExceptionMapper;
import org.whispersystems.textsecuregcm.util.NonNormalizedPrincipalException;

public class NonNormalizedPrincipalExceptionMapper implements ExceptionMapper<NonNormalizedPrincipalException> {

  private static final String NON_NORMALIZED_PRINCIPAL_COUNTER_NAME =
      name(NonNormalizedPrincipalExceptionMapper.class, "nonNormalizedPrincipals");

  @Override
  public Response toResponse(final NonNormalizedPrincipalException exception) {
    return Response.status(Status.BAD_REQUEST)
        .entity(new NonNormalizedPrincipalResponse(exception.getOriginalPrincipal(), exception.getNormalizedPrincipal()))
        .build();
  }
}
