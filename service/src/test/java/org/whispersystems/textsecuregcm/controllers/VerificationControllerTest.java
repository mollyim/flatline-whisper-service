/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.created;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.serverError;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.google.common.net.HttpHeaders;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.configuration.VerificationConfiguration;
import org.whispersystems.textsecuregcm.configuration.VerificationProviderConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicRegistrationConfiguration;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponse;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponseItem;
import org.whispersystems.textsecuregcm.entities.CreateVerificationSessionResponse;
import org.whispersystems.textsecuregcm.limits.RateLimitByIpFilter;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.ImpossiblePrincipalExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.NonNormalizedPrincipalExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.ObsoletePrincipalFormatExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.RegistrationServiceSenderExceptionMapper;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.storage.PrincipalNameIdentifiers;
import org.whispersystems.textsecuregcm.storage.RegistrationRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.VerificationSessionManager;
import org.whispersystems.textsecuregcm.util.MockUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestRemoteAddressFilterProvider;

@ExtendWith(DropwizardExtensionsSupport.class)
class VerificationControllerTest {
  private static final String EXAMPLE_AUTHORIZATION_PATH = "/api/oidc/authorization";
  private static final String EXAMPLE_TOKEN_PATH = "/api/oidc/token";
  private static final String EXAMPLE_PAR_PATH = "/api/oidc/pushed-authorization-request";
  private static final String EXAMPLE_JWKS_PATH = "/.well-known/jwks.json";

  private static final String EXAMPLE_CODE_CHALLENGE = "c3VwZXJzZWNyZXRfYXV0aF9jb2RlQmFzZQ";
  private static final String EXAMPLE_CODER_VERIFIER = "f83Jt8a9K7v1QzYpR4s2L0mN6bXcD5eFvGhIjKlMnOpQrStU";
  private static final String EXAMPLE_CODE = "SplxlOBeZQQYbYS6WxSbIA";
  private static final String EXAMPLE_STATE = "9b6a0ecb-4280-4743-8cbd-354e6eb68adc";
  private static final String EXAMPLE_NONCE = "88668681-f1a7-4a6e-89b2-552d58947c6a";
  private static final String EXAMPLE_REDIRECT_URI = "android-app:com.example.app:/oidc/callback";

  private static final String EXAMPLE_REQUEST_URI = "https://auth.example.com/e8786e71-3d9f-4b2b-91ba-5c8c2f9cd985";
  private static final long EXAMPLE_REQUEST_URI_LIFETIME = Duration.ofSeconds(10).toSeconds();

  private static final String EXAMPLE_TOKEN_TYPE = "Bearer";
  private static final long EXAMPLE_TOKEN_EXPIRATION = Duration.ofMinutes(5).toSeconds();
  private static final String EXAMPLE_TOKEN_SCOPE = "openid email profile";

  private static final byte[] SESSION_ID = "session".getBytes(StandardCharsets.UTF_8);
  private static final String PRINCIPAL = "user.account@example.com";
  private static final String SUBJECT = "25d8f276-120a-4b7c-8c80-f6e237d5e602";

  @RegisterExtension
  private static final WireMockExtension wireMock = WireMockExtension.newInstance()
      .options(wireMockConfig().dynamicPort().dynamicHttpsPort())
      .build();

  private static RSAKey PROVIDER_JWK;
  private static String PROVIDER_JWKS;
  private static VerificationProviderConfiguration PROVIDER_1;
  private static VerificationProviderConfiguration PROVIDER_2;
  @BeforeEach
  void init() throws Exception {
    PROVIDER_1 = new VerificationProviderConfiguration(
        "example-1",
        "Example 1",
        "https://auth1.example.com",
        "http://localhost:" + wireMock.getPort() + EXAMPLE_AUTHORIZATION_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_TOKEN_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_PAR_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_JWKS_PATH,
        "0e0ccedd-8d6c-4530-b277-5042ea7ead5b",
        "https://flatline.example.com", "openid profile", "sub");
    PROVIDER_2 = new VerificationProviderConfiguration(
        "example-2",
        "Example 2",
        "https://auth2.example.com",
        "http://localhost:" + wireMock.getPort() + EXAMPLE_AUTHORIZATION_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_TOKEN_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_PAR_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_JWKS_PATH,
        "2082720b-2922-459a-b9d4-935f8dd651bd",
        "https://flatline.example.com", "openid email profile", "email");

    PROVIDER_JWK = generateKeyPair("example-key-1");
    PROVIDER_JWKS = generateKeyJwks(PROVIDER_JWK);
  }

  private static final UUID PNI = UUID.randomUUID();
  private final VerificationSessionManager verificationSessionManager = mock(VerificationSessionManager.class);
  private final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager = mock(
      RegistrationRecoveryPasswordsManager.class);
  private final PrincipalNameIdentifiers principalNameIdentifiers = mock(PrincipalNameIdentifiers.class);
  private final RateLimiters rateLimiters = mock(RateLimiters.class);
  private final AccountsManager accountsManager = mock(AccountsManager.class);
  private static final Clock clock = Clock.systemUTC();

  private final RateLimiter authorizationLimiter = mock(RateLimiter.class);
  private final RateLimiter tokenExchangeLimiter = mock(RateLimiter.class);
  private final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager = mock(
      DynamicConfigurationManager.class);
  private final DynamicConfiguration dynamicConfiguration = mock(DynamicConfiguration.class);
  private final VerificationConfiguration verificationConfiguration = mock(VerificationConfiguration.class);

  private final ResourceExtension resources = ResourceExtension.builder()
      .addProperty(ServerProperties.UNWRAP_COMPLETION_STAGE_IN_WRITER_ENABLE, Boolean.TRUE)
      .addProvider(new RateLimitExceededExceptionMapper())
      .addProvider(new ImpossiblePrincipalExceptionMapper())
      .addProvider(new NonNormalizedPrincipalExceptionMapper())
      .addProvider(new ObsoletePrincipalFormatExceptionMapper())
      .addProvider(new RegistrationServiceSenderExceptionMapper())
      .addProvider(new TestRemoteAddressFilterProvider("127.0.0.1"))
      .addProvider(new RateLimitByIpFilter(rateLimiters))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(
          new VerificationController(verificationSessionManager,
              registrationRecoveryPasswordsManager, principalNameIdentifiers, rateLimiters,
              verificationConfiguration, clock))
      .build();

  @BeforeEach
  void setUp() {
    when(rateLimiters.getVerificationTokenExchangeLimiter())
        .thenReturn(tokenExchangeLimiter);
    when(rateLimiters.forDescriptor(RateLimiters.For.VERIFICATION_AUTHORIZATION_PER_IP))
        .thenReturn(authorizationLimiter);
    when(accountsManager.getByPrincipal(any()))
        .thenReturn(Optional.empty());
    when(dynamicConfiguration.getRegistrationConfiguration())
        .thenReturn(new DynamicRegistrationConfiguration(false));
    when(dynamicConfigurationManager.getConfiguration())
        .thenReturn(dynamicConfiguration);
    when(verificationConfiguration.getProviders())
        .thenReturn(List.of(PROVIDER_1, PROVIDER_2));
    when(verificationConfiguration.getProvider(PROVIDER_1.getId()))
        .thenReturn(PROVIDER_1);
    when(verificationConfiguration.getProvider(PROVIDER_2.getId()))
        .thenReturn(PROVIDER_2);
    when(principalNameIdentifiers.getPrincipalNameIdentifier(PRINCIPAL))
        .thenReturn(CompletableFuture.completedFuture(PNI));

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_PAR_PATH))
        .willReturn(created()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "request_uri": "%s",
                   "expires_in": %d
                }
                """.formatted(EXAMPLE_REQUEST_URI, EXAMPLE_REQUEST_URI_LIFETIME))));

    wireMock.stubFor(get(urlEqualTo(EXAMPLE_JWKS_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody(PROVIDER_JWKS)));
  }

  @MethodSource
  void createSessionUnprocessableRequestJson(final String providerId, final String codeChallenge,
      final String state, final String redirectUri) {
    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request();
    try (Response response = request.post(
        Entity.json(unprocessableCreateSessionJson(providerId, codeChallenge, state, redirectUri)))) {
      assertEquals(400, response.getStatus());
    }
  }

  @Test
  void getVerificationProviders() {
    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final VerificationProvidersResponse verificationProvidersResponse = response.readEntity(
          VerificationProvidersResponse.class);
      final List<VerificationProvidersResponseItem> providers = verificationProvidersResponse.getProviders();
      assertEquals(2, providers.size());

      final VerificationProvidersResponseItem provider1 = providers.get(0);
      assertEquals(PROVIDER_1.getId(), provider1.getId());
      assertEquals(PROVIDER_1.getName(), provider1.getName());
      assertEquals(PROVIDER_1.getIssuer(), provider1.getIssuer());
      assertEquals(PROVIDER_1.getAuthorizationEndpoint(), provider1.getAuthorizationEndpoint());
      assertEquals(PROVIDER_1.getPrincipalClaim(), provider1.getPrincipalClaim());

      final VerificationProvidersResponseItem provider2 = providers.get(1);
      assertEquals(PROVIDER_2.getId(), provider2.getId());
      assertEquals(PROVIDER_2.getName(), provider2.getName());
      assertEquals(PROVIDER_2.getIssuer(), provider2.getIssuer());
      assertEquals(PROVIDER_2.getAuthorizationEndpoint(), provider2.getAuthorizationEndpoint());
      assertEquals(PROVIDER_2.getPrincipalClaim(), provider2.getPrincipalClaim());
    }
  }

  @Test
  void createSessionRateLimited() throws Exception {
    when(verificationSessionManager.insert(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    MockUtils.updateRateLimiterResponseToFail(
        rateLimiters, RateLimiters.For.VERIFICATION_AUTHORIZATION_PER_IP, "127.0.0.1", Duration.ofMinutes(10));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(
        createSessionJson(PROVIDER_1.getId(), EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI)))) {
      assertEquals(429, response.getStatus());
    }
  }

  @ParameterizedTest
  @MethodSource
  void createSessionInvalidRequestJson(final String providerId, final String codeChallenge,
      final String state, final String redirectUri) {

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(createSessionJson(providerId, codeChallenge, state, redirectUri)))) {
      assertEquals(422, response.getStatus());
    }
  }

  static Stream<Arguments> createSessionInvalidRequestJson() {
    return Stream.of(
        Arguments.of("", EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI),
        Arguments.of(PROVIDER_1.getId(), "", EXAMPLE_STATE, EXAMPLE_REDIRECT_URI),
        Arguments.of("", EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI),
        Arguments.of(PROVIDER_1.getId(), EXAMPLE_CODE_CHALLENGE, "", EXAMPLE_REDIRECT_URI)
    );
  }

  @Test
  void createSessionInvalidProvider() {
    when(verificationSessionManager.insert(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(createSessionJson(
        "invalid-provider", EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI)))) {
      assertEquals(400, response.getStatus());
    }
  }

  @Test
  void createSessionParError() {
    wireMock.stubFor(post(urlEqualTo(EXAMPLE_PAR_PATH))
        .willReturn(serverError()));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(
        createSessionJson(PROVIDER_1.getId(), EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("pushed authorization request with the verification provider failed"));
    }
  }

  @Test
  void createSessionParInvalidResponse() {
    wireMock.stubFor(post(urlEqualTo(EXAMPLE_PAR_PATH))
        .willReturn(created()
            .withHeader("Content-Type", "application/json")
            .withBody("invalid")));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(
        createSessionJson(PROVIDER_1.getId(), EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("pushed authorization request with the verification provider failed"));
    }
  }

  @Test
  void createSessionParFailedConnect() {
    wireMock.stubFor(post(urlEqualTo(EXAMPLE_PAR_PATH))
        .willReturn(aResponse().withFault(Fault.EMPTY_RESPONSE)));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(
        createSessionJson(PROVIDER_1.getId(), EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("pushed authorization request with the verification provider failed"));
    }
  }

  @ParameterizedTest
  @MethodSource
  void createSessionSuccess(final String providerId, final String clientId, final String authorizationEndpoint) {

    when(verificationSessionManager.insert(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(
        createSessionJson(providerId, EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());
      verify(verificationSessionManager).insert(
          // The session identifier is created by the controller.
          any(),
          argThat(verification -> verificationSessionEquals(verification, new VerificationSession(
                  // Provider metadata should match the provider used to verify.
                  providerId, clientId,
                  EXAMPLE_STATE, EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE,
                  // The nonce is generated by the verification controller. Null represents any value.
                  null, EXAMPLE_REQUEST_URI,
                  // Principal and subject are not known yet.
                  null, null,
                  // Verification should be incomplete.
                  false,
                  // Timestamps should be updated to the current time.
                  clock.millis(), clock.millis(), EXAMPLE_REQUEST_URI_LIFETIME
              ))
          ));


      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);
      assertEquals(authorizationEndpoint, verificationSessionResponse.authorizationEndpoint());
      assertEquals(clientId, verificationSessionResponse.clientId());
      assertEquals(EXAMPLE_REQUEST_URI, verificationSessionResponse.requestUri());
      assertEquals(EXAMPLE_REQUEST_URI_LIFETIME, verificationSessionResponse.requestUriLifetime());
      assertFalse(verificationSessionResponse.id().isEmpty());
      assertFalse(verificationSessionResponse.verified());
    }
  }

  static Stream<Arguments> createSessionSuccess() {
    return Stream.of(
        Arguments.of(PROVIDER_1.getId(), PROVIDER_1.getClientId(), PROVIDER_1.getAuthorizationEndpoint()),
        Arguments.of(PROVIDER_2.getId(), PROVIDER_2.getClientId(), PROVIDER_2.getAuthorizationEndpoint())
        );
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void createSessionReregistration(final boolean isReregistration) {

    when(verificationSessionManager.insert(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    when(accountsManager.getByPrincipal(PRINCIPAL))
        .thenReturn(isReregistration ? Optional.of(mock(Account.class)) : Optional.empty());

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");

    try (final Response response = request.post(Entity.json(createSessionJson(PROVIDER_1.getId(), EXAMPLE_CODE_CHALLENGE, EXAMPLE_STATE, EXAMPLE_REDIRECT_URI)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      // FLT(uoemai): TODO: Look into whether this needs to be tested here.
    }
  }

  @Test
  void patchSessionMalformedId() {
    final String invalidSessionId = "()()()";

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + invalidSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json("{}"))) {
      assertEquals(HttpStatus.SC_UNPROCESSABLE_ENTITY, response.getStatus());
    }
  }

  @Test
  void patchSessionNotFound() {
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatus());
    }
  }

  @Test
  void patchSessionRateLimited() throws Exception {
    final String encodedSessionId = encodeSessionId(SESSION_ID);

    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    doThrow(RateLimitExceededException.class)
        .when(tokenExchangeLimiter).validate(anyString());

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);
      assertNull(verificationSessionResponse);
    }
  }

  @Test
  void patchSessionAlreadyVerified() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, PRINCIPAL, SUBJECT, true,
                clock.millis(), clock.millis(), clock.millis()))));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_CONFLICT, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("the verification session is already verified"));
    }
  }


  @Test
  void patchSessionInvalidProvider() {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession("invalid-provider",PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("the requested verification provider is invalid"));
    }
  }

  @Test
  void patchSessionInvalidRedirectUri() {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                ":invalid-redirect-uri", EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("the provided redirect URI is invalid"));
    }
  }

  @Test
  void patchSessionTokenExchangeFailedConnect() {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(aResponse().withFault(Fault.EMPTY_RESPONSE)));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("token exchange with verification provider failed"));
    }
  }

  @Test
  void patchSessionTokenExchangeFailedParse() {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("invalid")));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("token exchange with verification provider failed"));
    }
  }

  @Test
  void patchSessionTokenExchangeFailedResponse() {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(serverError()));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("token exchange with the verification provider failed"));
    }
  }

  @Test
  void patchSessionNoneAlgorithm() throws Exception {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    final String identityToken = generateInsecureIdentityTokenJwt(
        PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(),
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, "irrelevant", "irrelevant");
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));


    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("failed to verify token returned by the verification provider"));
    }
  }

  @Test
  void patchSessionInvalidJwksUrl() throws Exception {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    VerificationProviderConfiguration providerInvalidJwksUrl = new VerificationProviderConfiguration(
        "example-1",
        "Example 1",
        "https://auth1.example.com",
        "http://localhost:" + wireMock.getPort() + EXAMPLE_AUTHORIZATION_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_TOKEN_PATH,
        "http://localhost:" + wireMock.getPort() + EXAMPLE_PAR_PATH,
        // Invalid JWKS URL.
        "invalid",
        "0e0ccedd-8d6c-4530-b277-5042ea7ead5b",
        "https://flatline.example.com", "openid profile", "sub");
    when(verificationConfiguration.getProvider(providerInvalidJwksUrl.getId()))
        .thenReturn(providerInvalidJwksUrl);

    final String identityToken = generateIdentityTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(),
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, "irrelevant", "irrelevant");
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("failed to verify token returned by the verification provider"));
    }
  }

  @Test
  void patchSessionRetrieveJwksFailedConnect() throws Exception {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    wireMock.stubFor(get(urlEqualTo(EXAMPLE_JWKS_PATH))
        .willReturn(aResponse().withFault(Fault.EMPTY_RESPONSE)));

    final String identityToken = generateIdentityTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(),
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, "irrelevant", "irrelevant");
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("failed to verify token returned by the verification provider"));
    }
  }

  @Test
  void patchSessionRetrieveJwksFailedParse() throws Exception {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    wireMock.stubFor(get(urlEqualTo(EXAMPLE_JWKS_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("invalid")));

    final String identityToken = generateIdentityTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(),
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, "irrelevant", "irrelevant");
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("failed to verify token returned by the verification provider"));
    }
  }

  @ParameterizedTest
  @MethodSource
  void patchSessionInvalidClaims(String issuer, String subject, String audience, String nonce, long lifetime) throws Exception {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    final String identityToken = generateIdentityTokenJwt(
        PROVIDER_JWK, issuer, subject, audience,
        lifetime, nonce, "irrelevant", "irrelevant");
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("failed to verify token returned by the verification provider"));
    }
  }

  static Stream<Arguments> patchSessionInvalidClaims() {
    return Stream.of(
        // Invalid issuer.
        Arguments.of("invalid", SUBJECT, PROVIDER_1.getClientId(), EXAMPLE_NONCE, 10000),
        // Invalid subject. Missing or empty claim.
        Arguments.of(PROVIDER_1.getIssuer(), "", PROVIDER_1.getClientId(), EXAMPLE_NONCE, 10000),
        // Invalid audience.
        Arguments.of(PROVIDER_1.getIssuer(), SUBJECT, "invalid", EXAMPLE_NONCE, 10000),
        // Invalid nonce.
        Arguments.of(PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), "invalid", 10000),
        // Expired token. Lifetime is negative.
        Arguments.of(PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), EXAMPLE_NONCE, -100000)
    );
  }

  @Test
  void patchSessionInvalidSignature() throws Exception {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    // The key identifier matches, but the keys themselves will not.
    RSAKey invalidJwk = generateKeyPair("example-key-1");

    final String identityToken = generateIdentityTokenJwt(
        invalidJwk, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(),
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, "irrelevant", "irrelevant");
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));


    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("failed to verify token returned by the verification provider"));
    }
  }

  @Test
  void patchSessionMissingPrincipalClaim() throws Exception {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_2.getId(),PROVIDER_2.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), clock.millis(), clock.millis()))));

    final String identityToken = generateIdentityTokenJwt(
        PROVIDER_JWK, PROVIDER_2.getIssuer(), SUBJECT, PROVIDER_2.getClientId(),
        // The principal claim added to the token has an unexpected key.
        // This key is different from the principal claim configured for PROVIDER_2.
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, "unexpected", "irrelevant");
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));


    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {
      assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatus());
      String body = response.readEntity(String.class);
      assertNotNull(body);
      assertTrue(body.contains("failed to verify token returned by the verification provider"));
    }
  }

  @Test
  void patchSessionSuccess() throws Exception {
    when(verificationSessionManager.findForId(eq(encodeSessionId(SESSION_ID))))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), 0, EXAMPLE_REQUEST_URI_LIFETIME))));
    when(verificationSessionManager.update(eq(encodeSessionId(SESSION_ID)), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    // This provider uses the default "sub" claim for the principal.
    when(principalNameIdentifiers.getPrincipalNameIdentifier(eq(SUBJECT)))
        .thenReturn(CompletableFuture.completedFuture(UUID.randomUUID()));

    // The identity token is not expected to contain any additional principal claims.
    final String identityToken = generateIdentityTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(),
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, "irrelevant", "irrelevant");
    // This token is irrelevant for Flatline but still expected by the Nimbus library.
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_1.getIssuer(), SUBJECT, PROVIDER_1.getClientId(), PROVIDER_1.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, "irrelevant", "irrelevant");

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {

      verify(verificationSessionManager).findForId(eq(encodeSessionId(SESSION_ID)));
      verify(verificationSessionManager).update(
          eq(encodeSessionId(SESSION_ID)),
          argThat(verification -> verificationSessionEquals(verification, new VerificationSession(
                  // Provider metadata should match the provider used to verify.
                  PROVIDER_1.getId(), PROVIDER_1.getClientId(),
                  EXAMPLE_STATE, EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE,
                  EXAMPLE_NONCE, EXAMPLE_REQUEST_URI,
                  // Principal and subject should match.
                  SUBJECT, SUBJECT,
                  // Verification should be complete.
                  true,
                  // Timestamps should be updated to the current time.
                  clock.millis(), clock.millis(), EXAMPLE_REQUEST_URI_LIFETIME
              ))
          ));

      assertEquals(HttpStatus.SC_OK, response.getStatus());
    }
  }

  @Test
  void patchSessionSuccessPrincipalClaim() throws Exception {
    when(verificationSessionManager.findForId(eq(encodeSessionId(SESSION_ID))))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_2.getId(),PROVIDER_2.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, "", "", false,
                clock.millis(), 0, EXAMPLE_REQUEST_URI_LIFETIME))));
    when(verificationSessionManager.update(eq(encodeSessionId(SESSION_ID)), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    // This provider uses the custom "email" claim for the principal.
    // The identity token is expected to contain that additional claim with the principal.
    final String identityToken = generateIdentityTokenJwt(
        PROVIDER_JWK, PROVIDER_2.getIssuer(), SUBJECT, PROVIDER_2.getClientId(),
        EXAMPLE_REQUEST_URI_LIFETIME, EXAMPLE_NONCE, PROVIDER_2.getPrincipalClaim(), PRINCIPAL);
    // This token is irrelevant for Flatline but still expected by the Nimbus library.
    final String accessToken = generateAccessTokenJwt(
        PROVIDER_JWK, PROVIDER_2.getIssuer(), SUBJECT, PROVIDER_2.getClientId(), PROVIDER_2.getScopes(),
        EXAMPLE_REQUEST_URI_LIFETIME, PROVIDER_2.getPrincipalClaim(), PRINCIPAL);

    wireMock.stubFor(post(urlEqualTo(EXAMPLE_TOKEN_PATH))
        .willReturn(ok()
            .withHeader("Content-Type", "application/json")
            .withBody("""
                {
                   "id_token": "%s",
                   "access_token": "%s",
                   "token_type": "%s",
                   "expires_in": %d,
                   "scope": "%s"
                }
                """.formatted(
                identityToken, accessToken, EXAMPLE_TOKEN_TYPE, EXAMPLE_TOKEN_EXPIRATION, EXAMPLE_TOKEN_SCOPE))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(
        EXAMPLE_CODE, EXAMPLE_CODER_VERIFIER, EXAMPLE_STATE)))) {

      verify(verificationSessionManager).findForId(eq(encodeSessionId(SESSION_ID)));
      verify(verificationSessionManager).update(
          eq(encodeSessionId(SESSION_ID)),
          argThat(verification -> verificationSessionEquals(verification, new VerificationSession(
                  // Provider metadata should match the provider used to verify.
                  PROVIDER_2.getId(), PROVIDER_2.getClientId(),
                  EXAMPLE_STATE, EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE,
                  EXAMPLE_NONCE, EXAMPLE_REQUEST_URI,
                  // Principal and subject should be distinct.
                  PRINCIPAL, SUBJECT,
                  // Verification should be complete.
                  true,
                  // Timestamps the update timestamp should be updated to the current time.
                  clock.millis(), clock.millis(), EXAMPLE_REQUEST_URI_LIFETIME
              ))
          ));

      assertEquals(HttpStatus.SC_OK, response.getStatus());
    }
  }

  @Test
  void getSessionNotFound() {
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatus());
    }

    request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatus());
    }
  }

  @Test
  void getSessionSuccess() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);

    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(PROVIDER_1.getId(),PROVIDER_1.getClientId(), EXAMPLE_STATE,
                EXAMPLE_REDIRECT_URI, EXAMPLE_CODE_CHALLENGE, EXAMPLE_NONCE, EXAMPLE_REQUEST_URI, PRINCIPAL, SUBJECT, true,
                clock.millis(), clock.millis(), clock.millis()))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());
    }
  }

  /**
   * Request JSON in the shape of {@link org.whispersystems.textsecuregcm.entities.CreateVerificationSessionRequest}
   */
  private static String createSessionJson(final String providerId, final String codeChallenge,
      final String state, final String redirectUri) {
    return String.format("""
        {
          "providerId": %s,
          "codeChallenge": %s,
          "state": %s,
          "redirectUri": %s
        }
        """,
        quoteIfNotNull(providerId), quoteIfNotNull(codeChallenge), quoteIfNotNull(state), quoteIfNotNull(redirectUri));
  }

  /**
   * Request JSON in the shape of {@link org.whispersystems.textsecuregcm.entities.UpdateVerificationSessionRequest}
   */
  private static String updateSessionJson(final String code, final String codeVerifier, final String state) {
    return String.format("""
            {
              "code": %s,
              "codeVerifier": %s,
              "state": %s
            }
            """, quoteIfNotNull(code), quoteIfNotNull(codeVerifier), quoteIfNotNull(state));
  }

  private static String quoteIfNotNull(final String s) {
    return s == null ? null : StringUtils.join(new String[]{"\"", "\""}, s);
  }

  /**
   * Request JSON that cannot be marshalled into
   * {@link org.whispersystems.textsecuregcm.entities.CreateVerificationSessionRequest}
   */
  private static String unprocessableCreateSessionJson(final String providerId, final String codeChallenge,
      final String state, final String redirectUri) {
    return String.format("""
        {
          "providerId": %s,
          "codeChallenge": %s,
          "state": %s,
          "redirectUri": %s
        }
        """,
        quoteIfNotNull(providerId), quoteIfNotNull(codeChallenge), quoteIfNotNull(state), quoteIfNotNull(redirectUri));
  }

  private static String encodeSessionId(final byte[] sessionId) {
    return Base64.getUrlEncoder().encodeToString(sessionId);
  }

  private static RSAKey generateKeyPair(String kid) throws Exception {
    // Since the algorithm is responsibility of the Nimbus library, we use RSA for all tests.
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) kp.getPublic())
        .privateKey(kp.getPrivate())
        .keyID(kid)
        .build();
  }

  private static String generateKeyJwks(RSAKey jwk) throws Exception {
    JWKSet jwks = new JWKSet(jwk);
    return jwks.toPublicJWKSet().toString(true);
  }

  private static String generateIdentityTokenJwt(RSAKey jwk,
      String issuer, String subject, String audience, long lifetime, String nonce,
      String principalClaim, String principal) throws Exception {

    JWSSigner signer = new RSASSASigner(jwk);
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(subject)
        .audience(audience)
        .claim("nonce", nonce)
        .claim(principalClaim, principal)
        .issueTime(new Date())
        .notBeforeTime(new Date())
        .expirationTime(new Date(clock.millis() + lifetime))
        .build();

    SignedJWT signedJWT = new SignedJWT(
        // Since the algorithm is responsibility of the Nimbus library, we use RS256 for all tests.
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).type(JOSEObjectType.JWT).build(),
        claims
    );
    signedJWT.sign(signer);

    return signedJWT.serialize();
  }

  private static String generateAccessTokenJwt(RSAKey jwk,
      String issuer, String subject, String audience, String scope, long lifetime,
      String principalClaim, String principal) throws Exception {

    JWSSigner signer = new RSASSASigner(jwk);
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(subject)
        .audience(audience)
        .claim("scope", scope)
        .claim(principalClaim, principal)
        .issueTime(new Date())
        .notBeforeTime(new Date())
        .expirationTime(new Date(clock.millis() + lifetime))
        .build();

    SignedJWT signedJWT = new SignedJWT(
        // Since the algorithm is responsibility of the Nimbus library, we use RS256 for all tests.
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).type(JOSEObjectType.JWT).build(),
        claims
    );
    signedJWT.sign(signer);

    return signedJWT.serialize();
  }

  private static String generateInsecureIdentityTokenJwt(
      String issuer, String subject, String audience, long lifetime, String nonce,
      String principalClaim, String principal) {

    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(subject)
        .audience(audience)
        .claim("nonce", nonce)
        .claim(principalClaim, principal)
        .issueTime(new Date())
        .notBeforeTime(new Date())
        .expirationTime(new Date(clock.millis() + lifetime))
        .build();

    PlainHeader header = new PlainHeader.Builder().type(JOSEObjectType.JWT).build();
    PlainJWT plainJwt = new PlainJWT(header, claims);

    return plainJwt.serialize();
  }

  private static boolean verificationSessionEquals(final VerificationSession a, final VerificationSession b) {
    return a.providerId().equals(b.providerId())
        && a.clientId().equals(b.clientId())
        && a.state().equals(b.state())
        && a.redirectUri().equals(b.redirectUri())
        && a.codeChallenge().equals(b.codeChallenge())
        // In instances where the nonce is expected to be any value, a null value will be used.
        && a.nonce() == null || b.nonce() == null || a.nonce().equals(b.nonce())
        && a.requestUri().equals(b.requestUri())
        // The principal and subject need to be compared as nullable strings.
        && (a.principal() == b.principal() || (a.principal() != null && a.principal().equals(b.principal())))
        && (a.subject() == b.subject() || (a.subject() != null && a.subject().equals(b.subject())))
        && a.verified() == b.verified()
        // Timestamps should match within one second margin.
        && Math.abs(a.createdTimestamp() - b.createdTimestamp()) < 1000
        && Math.abs(a.updatedTimestamp() - b.updatedTimestamp()) < 1000
        && a.remoteExpirationSeconds() == b.remoteExpirationSeconds();
  }

}
