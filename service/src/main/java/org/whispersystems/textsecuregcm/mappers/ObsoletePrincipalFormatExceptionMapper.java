package org.whispersystems.textsecuregcm.mappers;

import io.micrometer.core.instrument.Metrics;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import org.whispersystems.textsecuregcm.metrics.MetricsUtil;
import org.whispersystems.textsecuregcm.util.ObsoletePrincipalFormatException;

public class ObsoletePrincipalFormatExceptionMapper implements ExceptionMapper<ObsoletePrincipalFormatException> {

  private static final String COUNTER_NAME = MetricsUtil.name(ObsoletePrincipalFormatExceptionMapper.class, "errors");

  @Override
  public Response toResponse(final ObsoletePrincipalFormatException exception) {
    Metrics.counter(COUNTER_NAME).increment();
    return Response.status(499).build();
  }
}
