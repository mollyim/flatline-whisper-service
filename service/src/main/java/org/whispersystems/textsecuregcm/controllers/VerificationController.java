/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.VerificationProviderConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.VerificationConfiguration;
import org.whispersystems.textsecuregcm.entities.CreateVerificationSessionRequest;
import org.whispersystems.textsecuregcm.entities.UpdateVerificationSessionRequest;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponse;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponseItem;
import org.whispersystems.textsecuregcm.entities.VerificationSessionResponse;
import org.whispersystems.textsecuregcm.limits.RateLimitedByIp;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.spam.RegistrationFraudChecker;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.storage.PrincipalNameIdentifiers;
import org.whispersystems.textsecuregcm.storage.RegistrationRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.VerificationSessionManager;
import org.whispersystems.textsecuregcm.util.SystemMapper;

@Path("/v1/verification")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Verification")
public class VerificationController {

  private static final Logger logger = LoggerFactory.getLogger(VerificationController.class);
  private static final Duration DYNAMODB_TIMEOUT = Duration.ofSeconds(5);

  private final RegistrationServiceClient registrationServiceClient;
  private final VerificationSessionManager verificationSessionManager;
  private final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager;
  private final PrincipalNameIdentifiers principalNameIdentifiers;
  private final RateLimiters rateLimiters;
  private final AccountsManager accountsManager;
  private final RegistrationFraudChecker registrationFraudChecker;
  private final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager;
  private final VerificationConfiguration verificationConfiguration;
  private final Clock clock;

  private record ParResponse(
        String request_uri,
        int expires_in) {
  }

  public VerificationController(final RegistrationServiceClient registrationServiceClient,
      final VerificationSessionManager verificationSessionManager,
      final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager,
      final PrincipalNameIdentifiers principalNameIdentifiers,
      final RateLimiters rateLimiters,
      final AccountsManager accountsManager,
      final RegistrationFraudChecker registrationFraudChecker,
      final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager,
      final VerificationConfiguration verificationConfiguration,
      final Clock clock) {
    this.registrationServiceClient = registrationServiceClient;
    this.verificationSessionManager = verificationSessionManager;
    this.registrationRecoveryPasswordsManager = registrationRecoveryPasswordsManager;
    this.principalNameIdentifiers = principalNameIdentifiers;
    this.rateLimiters = rateLimiters;
    this.accountsManager = accountsManager;
    this.registrationFraudChecker = registrationFraudChecker;
    this.dynamicConfigurationManager = dynamicConfigurationManager;
    this.verificationConfiguration = verificationConfiguration;
    this.clock = clock;
  }

  @GET
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Retrieve the list of verification providers",
      description = """
          Retrieves the list of verification providers that can be used to start a verification session.
          This list includes the details that the client needs to communicate with each provider.
          """)
  @ApiResponse(responseCode = "200", description = "The list of providers was retrieved", useReturnTypeSchema = true)
  public VerificationProvidersResponse getVerificationConfiguration() {
    final List<VerificationProvidersResponseItem> responseItems = verificationConfiguration.getProviders().stream()
        .map(provider -> new VerificationProvidersResponseItem(
            provider.getId(), provider.getName(), provider.getIssuer(),
            provider.getAuthorizationEndpoint(), provider.getPrincipalClaim())).toList();
    return new VerificationProvidersResponse(responseItems);
  }

  @POST
  @Path("/session")
  // FLT(uoemai): Prevent anonymous clients from causing Flatline to overload the identity provider.
  @RateLimitedByIp(RateLimiters.For.VERIFICATION_AUTHORIZATION_PER_IP)
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Creates a new verification session",
      description = """
          Initiates a session to be able to verify a principal for account registration. Expects to receive an
          authorization request for a chosen verification provider. Flatline will perform
          PAR (i.e. pushed authorization request) with the chosen verification provider and return the resulting
          authorization parameters to the client. The client is then expected to perform the authorization step and
          request PATCH /session/{sessionId} with the token exchange parameters.
          """)
  @ApiResponse(responseCode = "200", description = "The verification session was created successfully", useReturnTypeSchema = true)
  @ApiResponse(responseCode = "422", description = "The request did not pass validation")
  @ApiResponse(responseCode = "429", description = "Too many attempts", headers = @Header(
      name = "Retry-After",
      description = "If present, an positive integer indicating the number of seconds before a subsequent attempt could succeed",
      schema = @Schema(implementation = Integer.class)))
  public VerificationSessionResponse createSession(@NotNull @Valid final CreateVerificationSessionRequest request,
      @Context final ContainerRequestContext requestContext) {

    final VerificationProviderConfiguration provider = verificationConfiguration.getProvider(request.providerId());
    if (provider == null) {
      throw new ServerErrorException("the requested verification provider is invalid",
          Response.Status.BAD_REQUEST);
    }

    final String sessionId = UUID.randomUUID().toString();
    final String clientId = UUID.randomUUID().toString();
    final String nonce = UUID.randomUUID().toString();

    Map<String,String> parParams = Map.of(
        "client_id", clientId,
        "redirect_uri", request.redirectUri(),
        "state", request.state(),
        "nonce", nonce,
        "scope", provider.getScopes(),
        "response_type", "code",
        "code_challenge", "CODE_CHALLENGE",
        "code_challenge_method", "S256"
    );
    String parRequestBody = parParams.entrySet().stream()
        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
            + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .reduce((a,b) -> a + "&" + b).orElse("");
    HttpRequest parRequest = HttpRequest.newBuilder()
        .uri(URI.create(provider.getParEndpoint()))
        .timeout(Duration.ofSeconds(10))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(parRequestBody))
        .build();

    HttpResponse<String> parResponse;
    try(HttpClient client = HttpClient.newHttpClient();) {
      parResponse = client.send(parRequest, HttpResponse.BodyHandlers.ofString());
    } catch (Exception e) {
        throw new ServerErrorException("could not connect to the PAR endpoint from the verification provider",
            Response.Status.INTERNAL_SERVER_ERROR);
    }
    if (parResponse.statusCode() != Response.Status.CREATED.getStatusCode()) {
      throw new ServerErrorException("the verification provider failed to create a PAR URI",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    final ParResponse parResponseData;
    try {
      parResponseData = SystemMapper.jsonMapper()
          .readValue(parResponse.body(), ParResponse.class);
    } catch (JsonProcessingException e) {
      throw new ServerErrorException("could not parse the PAR response from the verification provider",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    final long parExpiration = 1000L * parResponseData.expires_in;
    VerificationSession verificationSession = new VerificationSession(provider.getId(), clientId,
       request.state(), request.redirectUri(), request.codeChallenge(), nonce,
       null, clock.millis(), clock.millis(), parExpiration);
    storeVerificationSession(sessionId, verificationSession);

    return new VerificationSessionResponse(sessionId, provider.getAuthorizationEndpoint(), clientId,
        parResponseData.request_uri, parResponseData.expires_in, false);
  }

  @PATCH
  @Path("/session/{sessionId}")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Update a registration verification session",
      description = """
          Updates the session with the token exchange parameters obtained by the client after completing the
          authorization step. Flatline will then exchange those parameters for a token from the verification provider,
          verify the signature and contents of the token as configured and create a verified registration session for an
          the principal matching the value in the token claim configured as the principal for the verification provider.
          """)
  @ApiResponse(responseCode = "200", description = "Session was updated successfully with the information provided", useReturnTypeSchema = true)
  @ApiResponse(responseCode = "403", description = "The information provided was not accepted (e.g token exchange failed)")
  @ApiResponse(responseCode = "422", description = "The request did not pass validation")
  @ApiResponse(responseCode = "429", description = "Too many attempts",
      content = @Content(schema = @Schema(implementation = VerificationSessionResponse.class)),
      headers = @Header(
          name = "Retry-After",
          description = "If present, an positive integer indicating the number of seconds before a subsequent attempt could succeed",
          schema = @Schema(implementation = Integer.class)))
  public VerificationSessionResponse updateSession(
      @PathParam("sessionId") final String sessionId,
      @HeaderParam(HttpHeaders.USER_AGENT) final String userAgent,
      @Context final ContainerRequestContext requestContext,
      @NotNull @Valid final UpdateVerificationSessionRequest updateVerificationSessionRequest) throws RateLimitExceededException {


    VerificationSession verificationSession = retrieveVerificationSession(sessionId);
    // FLT(uoemai): Prevent clients from causing Flatline to overload the identity provider.
    rateLimiters.getVerificationTokenExchangeLimiter().validate(sessionId);

    // Use token exchange parameters to obtain a token from the provider matching the provided ID.
    // Verify that the token signature matches JWKs, is not expired, matches nonce
    // Cache the found JWKS for the provider
    // Verify that the token has the principal claim
    // Validate the principal
    // final Principal principal;
    //    try {
    //      // FLT(uoemai): Canonicalization no longer applies to phone numbers specifically, only to principals.
    //      //              With principals, technically equivalent phone numbers are treated as different principals.
    //      principal = Principal.parse(Util.canonicalizePrincipal(request.principal()));
    //    } catch (final InvalidPrincipalException e) {
    //      throw new ServerErrorException("could not parse already validated principal", Response.Status.INTERNAL_SERVER_ERROR);
    //    }
    // Otherwise return a 403
    // Update the verification session with all the missing data:
    // updateStoredVerificationSession(registrationServiceSession, verificationSession)
    // Return a 200 response

    return null;
  }

  private void updateStoredVerificationSession(final String sessionId,
      final VerificationSession verificationSession) {
    verificationSessionManager.update(sessionId, verificationSession)
        .orTimeout(DYNAMODB_TIMEOUT.toSeconds(), TimeUnit.SECONDS)
        .join();
  }

  @GET
  @Path("/session/{sessionId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a registration verification session",
      description = """
          Retrieve metadata of the registration verification session with the specified ID
          """)
  @ApiResponse(responseCode = "200", description = "Session was retrieved successfully", useReturnTypeSchema = true)
  @ApiResponse(responseCode = "400", description = "Invalid session ID")
  @ApiResponse(responseCode = "404", description = "Session with the specified ID could not be found")
  @ApiResponse(responseCode = "422", description = "Malformed session ID encoding")
  public VerificationSessionResponse getSession(@PathParam("sessionId") final String sessionId) {

    final VerificationSession verificationSession = retrieveVerificationSession(sessionId);

    // TODO: Consider if we really want to have this endpoint.
    // TODO: If we do, return only the fields that can be public.

    return null;
  }

  private void storeVerificationSession(String sessionId, final VerificationSession verificationSession) {
    verificationSessionManager.insert(sessionId, verificationSession)
        .orTimeout(DYNAMODB_TIMEOUT.toSeconds(), TimeUnit.SECONDS)
        .join();
  }

  /**
   * @throws NotFoundException if the session has no record
   */
  private VerificationSession retrieveVerificationSession(final String sessionId) {
    return verificationSessionManager.findForId(sessionId)
        .orTimeout(5, TimeUnit.SECONDS)
        .join().orElseThrow(NotFoundException::new);
  }
}
