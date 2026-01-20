/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest;
import com.nimbusds.oauth2.sdk.PushedAuthorizationResponse;
import com.nimbusds.oauth2.sdk.PushedAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.BadRequestException;
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
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.VerificationProviderConfiguration;
import org.whispersystems.textsecuregcm.configuration.VerificationConfiguration;
import org.whispersystems.textsecuregcm.entities.CreateVerificationSessionRequest;
import org.whispersystems.textsecuregcm.entities.Principal;
import org.whispersystems.textsecuregcm.entities.UpdateVerificationSessionRequest;
import org.whispersystems.textsecuregcm.entities.UpdateVerificationSessionResponse;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponse;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponseItem;
import org.whispersystems.textsecuregcm.entities.CreateVerificationSessionResponse;
import org.whispersystems.textsecuregcm.limits.RateLimitedByIp;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.storage.PrincipalNameIdentifiers;
import org.whispersystems.textsecuregcm.storage.RegistrationRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.VerificationSessionManager;
import org.whispersystems.textsecuregcm.util.InvalidPrincipalException;
import org.whispersystems.textsecuregcm.util.Util;

// FLT(uoemai): This controller has been completely rewritten for Flatline.
//              All comments in this controller are from the Flatline project, even if missing the FLT prefix.
//              This controller verifies that a client has ownership of a specific principal in at least
//              one of the verification providers that have been configured by the Flatline operator.
@Path("/v1/verification")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Verification")
public class VerificationController {

  private static final Logger logger = LoggerFactory.getLogger(VerificationController.class);
  private static final Duration DYNAMODB_TIMEOUT = Duration.ofSeconds(5);

  private final VerificationSessionManager verificationSessionManager;
  private final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager;
  private final PrincipalNameIdentifiers principalNameIdentifiers;
  private final RateLimiters rateLimiters;
  private final VerificationConfiguration verificationConfiguration;
  private final Clock clock;

  private record ParResponse(
        String request_uri,
        int expires_in) {
  }

  public VerificationController(
      final VerificationSessionManager verificationSessionManager,
      final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager,
      final PrincipalNameIdentifiers principalNameIdentifiers,
      final RateLimiters rateLimiters,
      final VerificationConfiguration verificationConfiguration,
      final Clock clock) {
    this.verificationSessionManager = verificationSessionManager;
    this.registrationRecoveryPasswordsManager = registrationRecoveryPasswordsManager;
    this.principalNameIdentifiers = principalNameIdentifiers;
    this.rateLimiters = rateLimiters;
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
  // This rate limiting mitigates anonymous clients causing Flatline to overload the identity provider.
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
  public CreateVerificationSessionResponse createSession(@NotNull @Valid final CreateVerificationSessionRequest request,
      @Context final ContainerRequestContext requestContext) {

    final VerificationProviderConfiguration provider = verificationConfiguration.getProvider(request.providerId());
    if (provider == null) {
      logger.info("failed to find verification provider requested by the verification client");
      throw new BadRequestException("the requested verification provider is invalid");
    }

    final String sessionId = UUID.randomUUID().toString();
    final Nonce nonce = new Nonce();

    ClientID clientId = new ClientID(provider.getClientId());

    final AuthorizationRequest parRequest = new AuthorizationRequest.Builder(
        new ResponseType("code"), clientId)
        .redirectionURI(URI.create(request.redirectUri()))
        .scope(Scope.parse(provider.getScopes()))
        .state(new State(request.state()))
        .build();

    final HTTPRequest parHttpRequest = new PushedAuthorizationRequest(
        URI.create(provider.getParEndpoint()), parRequest)
        .toHTTPRequest();
    HTTPResponse parHttpResponse = null;
    try {
      parHttpResponse = parHttpRequest.send();
    } catch (IOException e) {
      logger.warn("PAR request to provider \"{}\" failed", provider.getId(), e);
      throw new ServerErrorException("pushed authorization request with the verification provider failed",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    PushedAuthorizationResponse parResponse = null;
    try {
      parResponse = PushedAuthorizationResponse.parse(parHttpResponse);
    } catch (ParseException e) {
      logger.warn("PAR response from provider \"{}\" failed to parse", provider.getId(), e);
      throw new ServerErrorException("pushed authorization request with the verification provider failed",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    if (!parResponse.indicatesSuccess()) {
      logger.warn("PAR request to provider \"{}\" was unsuccessful with status: {}, code: {}",
          provider.getId(),
          parResponse.toErrorResponse().getErrorObject().getHTTPStatusCode(),
          parResponse.toErrorResponse().getErrorObject().getCode());
      throw new ServerErrorException("pushed authorization request with the verification provider failed",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    final PushedAuthorizationSuccessResponse parData = parResponse.toSuccessResponse();
    final long parLifetimeMillis = 1000L * parData.getLifetime();
    final VerificationSession verificationSession = new VerificationSession(provider.getId(), clientId.toString(),
       request.state(), request.redirectUri(), request.codeChallenge(), nonce.toString(),
        parData.getRequestURI().toString(), null, null, false,
        clock.millis(), clock.millis(), parLifetimeMillis);
    storeVerificationSession(sessionId, verificationSession);

    return new CreateVerificationSessionResponse(sessionId, provider.getAuthorizationEndpoint(), clientId.toString(),
        parData.getRequestURI().toString(), parData.getLifetime(), false);
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
  @ApiResponse(responseCode = "404", description = "Session with the specified ID could not be found")
  @ApiResponse(responseCode = "422", description = "The request did not pass validation")
  @ApiResponse(responseCode = "429", description = "Too many attempts",
      content = @Content(schema = @Schema(implementation = CreateVerificationSessionResponse.class)),
      headers = @Header(
          name = "Retry-After",
          description = "If present, an positive integer indicating the number of seconds before a subsequent attempt could succeed",
          schema = @Schema(implementation = Integer.class)))
  public UpdateVerificationSessionResponse updateSession(
      @PathParam("sessionId") final String sessionId,
      @HeaderParam(HttpHeaders.USER_AGENT) final String userAgent,
      @Context final ContainerRequestContext requestContext,
      @NotNull @Valid final UpdateVerificationSessionRequest updateVerificationSessionRequest) throws RateLimitExceededException {


    VerificationSession verificationSession = retrieveVerificationSession(sessionId);
    // This rate limiting mitigates clients causing Flatline to overload the identity provider.
    rateLimiters.getVerificationTokenExchangeLimiter().validate(sessionId);

    if (verificationSession.verified()) {
      logger.debug("refused to update a session that is already verified");
      throw new WebApplicationException(
          Response.status(Response.Status.CONFLICT)
              .entity("the verification session is already verified")
              .type("text/plain")
              .build()
      );
    }

    final VerificationProviderConfiguration provider = verificationConfiguration.getProvider(verificationSession.providerId());
    if (provider == null) {
      logger.info("failed to find verification provider from the verification session");
      throw new BadRequestException("the requested verification provider is invalid");
    }

    final AuthorizationCode code = new AuthorizationCode(updateVerificationSessionRequest.code());
    CodeVerifier codeVerifier = new CodeVerifier(updateVerificationSessionRequest.codeVerifier());
    final URI redirectURI;
    try {
      redirectURI = new URI(verificationSession.redirectUri());
    } catch (URISyntaxException e) {
      logger.info("failed to parse redirect URI provided by the verification client", e);
      throw new ServerErrorException("the provided redirect URI is invalid",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    TokenRequest tokenRequest = new TokenRequest(
        URI.create(provider.getTokenEndpoint()),
        new ClientID(verificationSession.clientId()),
        new AuthorizationCodeGrant(code, redirectURI, codeVerifier),
        Scope.parse(provider.getScopes()));

    final TokenResponse tokenResponse;
    try {
      tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
    } catch (ParseException e) {
      logger.warn("failed to parse token response from verification provider", e);
      throw new ServerErrorException("token exchange with verification provider failed",
          Response.Status.INTERNAL_SERVER_ERROR);
    } catch (IOException e) {
      logger.warn("failed to request token from the verification provider", e);
      throw new ServerErrorException("token exchange with verification provider failed",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    if (! tokenResponse.indicatesSuccess()) {
      TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
      logger.warn("verification provider returned an error to token request: {}", errorResponse);
      throw new ServerErrorException("token exchange with the verification provider failed",
          Response.Status.INTERNAL_SERVER_ERROR);
    }
    final OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();

    // We retrieve the identity token from the OIDC response.
    final JWT idToken = successResponse.getOIDCTokens().getIDToken();

    // We verify the token against the expected issuer, client identifier and JWKS.
    final Issuer iss = new Issuer(provider.getIssuer());
    final ClientID clientId = new ClientID(verificationSession.clientId());
    // At this point, we allow any algorithm used to sign token as long as it is not "none".
    // Further down, we will also ensure that algorithm is allowed by the IdP in its JWKS.
    final JWSAlgorithm alg = new JWSAlgorithm(idToken.getHeader().getAlgorithm().toString());
    if (alg.equals(JWSAlgorithm.NONE)) {
      logger.warn("verification provider issued token using no signature algorithm");
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.INTERNAL_SERVER_ERROR);
    }
    final JWKSet jwks = retrieveJwksWithCache(provider.getJwksUri());
    final IDTokenValidator validator = new IDTokenValidator(iss, clientId, alg, jwks);
    final Nonce expectedNonce = new Nonce(verificationSession.nonce());

    IDTokenClaimsSet claims;
    try {
      // This validates the following:
      // - The token issuer matches the expected issuer.
      // - The token client identifier matches the one configured.
      // - The token nonce value matches the on in the verification session.
      // - The token is valid at this point, given 1 minute of leeway.
      // - The token has a valid signature with the selected key and algorithm.
      claims = validator.validate(idToken, expectedNonce);
    } catch (BadJOSEException e) {
      logger.error("failed to verify the signature or claims from the token returned by the verification provider", e);
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.UNAUTHORIZED);
    } catch (JOSEException e) {
      logger.error("failed to process the token returned by the verification provider", e);
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.UNAUTHORIZED);
    }

    // We verify that the expected audience is included in the "aud" claim.
    if(!claims.getAudience().contains(new Audience(provider.getAudience()))){
      logger.warn("token returned by the verification provider does not match the configured audience");
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.UNAUTHORIZED);
    }

    // We verify that the "sub" claim is present and store it.
    final String subject = claims.getStringClaim("sub");
    if (subject.isEmpty()) {
      logger.warn("token returned by the verification provider has an empty subject claim");
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.UNAUTHORIZED);
    }

    String principalClaim = (provider.getPrincipalClaim().isEmpty()) ? "sub" : provider.getPrincipalClaim();;
    Principal principal;
    try {
      // We verify that the configured principal claim (defaulting to "sub") is present in the token.
      // The value of the claim must also be a valid principal.
      principal = Principal.parse(Util.canonicalizePrincipal(claims.getStringClaim(principalClaim)));
    } catch (final InvalidPrincipalException e) {
      logger.warn("failed to parse principal from the token returned by the verification provider");
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.UNAUTHORIZED);
    }

    // Once the principal is validated, the recovery password is removed for the account with that principal.
    // The account must be registered with the verification session that will be returned at this point.
    registrationRecoveryPasswordsManager.remove(principalNameIdentifiers.getPrincipalNameIdentifier(principal.toString()).join());

    final VerificationSession verifiedVerificationSession = new VerificationSession(
        verificationSession.providerId(), verificationSession.clientId(),
        verificationSession.state(), verificationSession.redirectUri(), verificationSession.codeChallenge(),
        verificationSession.nonce(), verificationSession.requestUri(), principal.toString(), subject, true,
        verificationSession.createdTimestamp(), clock.millis(), verificationSession.remoteExpirationSeconds());
    storeVerificationSession(sessionId, verifiedVerificationSession);

    return new UpdateVerificationSessionResponse(sessionId, principal.toString(), true);
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
  public CreateVerificationSessionResponse getSession(@PathParam("sessionId") final String sessionId) {

    final VerificationSession verificationSession = retrieveVerificationSession(sessionId);
    final VerificationProviderConfiguration provider = verificationConfiguration.getProvider(verificationSession.providerId());

    return new CreateVerificationSessionResponse(sessionId, provider.getAuthorizationEndpoint(),
        verificationSession.clientId(), verificationSession.requestUri(),
        verificationSession.remoteExpirationSeconds(), verificationSession.verified());
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

  /**
   * Attempts to retrieve a JWKS object from the JWKS cache
   * If the object is not found in the cache, it will be retrieved from the provided URI
   * @throws NotFoundException if the object is retrieved from a URI that not point to a JWKS object
   */
  private JWKSet retrieveJwksWithCache(final String uri) {
    // FLT(uoemai): TODO: Attempt to fetch JWKS from cache by URI.

    URL url = null;
    try {
      url = new URL(uri);
    } catch (MalformedURLException e) {
      logger.warn("failed to parse JWKS URI for the verification provider", e);
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    JWKSet jwks;
    try {
      jwks = JWKSet.load(url);
    } catch (IOException e) {
      logger.warn("failed to retrieve JWKS from the verification provider", e);
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.INTERNAL_SERVER_ERROR);
    } catch (java.text.ParseException e) {
      logger.warn("failed to parse JWKS returned by the verification provider", e);
      throw new ServerErrorException("failed to verify token returned by the verification provider",
          Response.Status.INTERNAL_SERVER_ERROR);
    }

    // FLT(uoemai): TODO: Store JWKS in cache by URI.

    return jwks;
  }
}
