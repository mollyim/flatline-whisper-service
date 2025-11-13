/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.mappers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import org.whispersystems.textsecuregcm.util.ImpossiblePhoneNumberException;

public class ImpossiblePrincipalExceptionMapper implements ExceptionMapper<ImpossiblePhoneNumberException> {

  private static final Counter IMPOSSIBLE_PRINCIPAL_COUNTER =
      Metrics.counter(name(ImpossiblePrincipalExceptionMapper.class, "impossiblePrincipals"));

  @Override
  public Response toResponse(final ImpossiblePhoneNumberException exception) {
    IMPOSSIBLE_PRINCIPAL_COUNTER.increment();

    return Response.status(Response.Status.BAD_REQUEST).build();
  }
}
