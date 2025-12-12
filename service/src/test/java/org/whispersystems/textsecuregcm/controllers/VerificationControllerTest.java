/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.google.common.net.HttpHeaders;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.whispersystems.textsecuregcm.captcha.AssessmentResult;
import org.whispersystems.textsecuregcm.captcha.RegistrationCaptchaManager;
import org.whispersystems.textsecuregcm.configuration.VerificationConfiguration;
import org.whispersystems.textsecuregcm.configuration.VerificationProviderConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicRegistrationConfiguration;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponse;
import org.whispersystems.textsecuregcm.entities.VerificationProvidersResponseItem;
import org.whispersystems.textsecuregcm.entities.CreateVerificationSessionResponse;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.ImpossiblePrincipalExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.NonNormalizedPrincipalExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.ObsoletePrincipalFormatExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.RegistrationServiceSenderExceptionMapper;
import org.whispersystems.textsecuregcm.push.PushNotificationManager;
import org.whispersystems.textsecuregcm.registration.RegistrationFraudException;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceException;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceSenderException;
import org.whispersystems.textsecuregcm.registration.TransportNotAllowedException;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.spam.RegistrationFraudChecker;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.storage.PrincipalNameIdentifiers;
import org.whispersystems.textsecuregcm.storage.RegistrationRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.VerificationSessionManager;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestRemoteAddressFilterProvider;

@ExtendWith(DropwizardExtensionsSupport.class)
class VerificationControllerTest {

  private static final long SESSION_EXPIRATION_SECONDS = Duration.ofMinutes(10).toSeconds();

  private static final byte[] SESSION_ID = "session".getBytes(StandardCharsets.UTF_8);
  // FLT(uoemai): Pending the migration to OIDC registration, the principal is assumed to be a phone number.
  //              TODO: Migrate tests to use generic principals once registration is migrated to OIDC.
  private static final String PRINCIPAL = PhoneNumberUtil.getInstance().format(
      PhoneNumberUtil.getInstance().getExampleNumber("US"),
      PhoneNumberUtil.PhoneNumberFormat.E164);

  private static final VerificationProviderConfiguration PROVIDER_1 = new VerificationProviderConfiguration(
      "example-1",
      "Example 1",
      "https://auth1.example.com",
      "https://auth1.example.com/api/oidc/authorization",
      "https://auth1.example.com/api/oidc/token",
      "https://auth1.example.com/api/oidc/pushed-authorization-request",
      "https://auth1.example.com/.well-known/jwks.json",
      "0e0ccedd-8d6c-4530-b277-5042ea7ead5b",
      "https://flatline.example.com", "openid profile", "sub");
  private static final VerificationProviderConfiguration PROVIDER_2 = new VerificationProviderConfiguration(
      "example-2",
      "Example 2",
      "https://auth2.example.com",
      "https://auth2.example.com/api/oidc/authorization",
      "https://auth1.example.com/api/oidc/token",
      "https://auth2.example.com/api/oidc/pushed-authorization-request",
      "file:///opt/flatline/oidc/example-2/jwks.json",
      "2082720b-2922-459a-b9d4-935f8dd651bd",
      "https://flatline.example.com", "openid email profile", "email");

  private static final UUID PNI = UUID.randomUUID();
  private final RegistrationServiceClient registrationServiceClient = mock(RegistrationServiceClient.class);
  private final VerificationSessionManager verificationSessionManager = mock(VerificationSessionManager.class);
  private final PushNotificationManager pushNotificationManager = mock(PushNotificationManager.class);
  private final RegistrationCaptchaManager registrationCaptchaManager = mock(RegistrationCaptchaManager.class);
  private final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager = mock(
      RegistrationRecoveryPasswordsManager.class);
  private final PrincipalNameIdentifiers principalNameIdentifiers = mock(PrincipalNameIdentifiers.class);
  private final RateLimiters rateLimiters = mock(RateLimiters.class);
  private final AccountsManager accountsManager = mock(AccountsManager.class);
  private final Clock clock = Clock.systemUTC();

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
    when(accountsManager.getByPrincipal(any()))
        .thenReturn(Optional.empty());
    when(dynamicConfiguration.getRegistrationConfiguration())
        .thenReturn(new DynamicRegistrationConfiguration(false));
    when(dynamicConfigurationManager.getConfiguration())
        .thenReturn(dynamicConfiguration);
    when(verificationConfiguration.getProviders())
        .thenReturn(List.of(PROVIDER_1, PROVIDER_2));
    when(principalNameIdentifiers.getPrincipalNameIdentifier(PRINCIPAL))
        .thenReturn(CompletableFuture.completedFuture(PNI));
  }

  @MethodSource
  void createSessionUnprocessableRequestJson(final String principal, final String pushToken, final String pushTokenType) {

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request();
    try (Response response = request.post(
        Entity.json(unprocessableCreateSessionJson(principal, pushToken, pushTokenType)))) {
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

  static Stream<Arguments> createSessionUnprocessableRequestJson() {
    return Stream.of(
        Arguments.of("[]", null, null),
        Arguments.of(String.format("\"%s\"", PRINCIPAL), "some-push-token", "invalid-token-type")
    );
  }

  @ParameterizedTest
  @MethodSource
  void createSessionInvalidRequestJson(final String principal, final String pushToken, final String pushTokenType) {

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(createSessionJson(principal, pushToken, pushTokenType)))) {
      assertEquals(422, response.getStatus());
    }
  }

  static Stream<Arguments> createSessionInvalidRequestJson() {
    return Stream.of(
        Arguments.of(null, null, null),
        Arguments.of("invalid.principal.¥€Š", null, null),
        Arguments.of(" ", null, null)
        // FLT(uoemai): These test cases are not relevant while notifications are disabled.
        // Arguments.of(PRINCIPAL, null, "fcm"),
        // Arguments.of(PRINCIPAL, "some-push-token", null)
    );
  }

  @Test
  void createSessionRateLimited() {
    when(registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any()))
        .thenReturn(CompletableFuture.failedFuture(new RateLimitExceededException(null)));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(createSessionJson(PRINCIPAL, null, null)))) {
      assertEquals(429, response.getStatus());
    }
  }

  @Test
  void createSessionRegistrationServiceError() {
    when(registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any()))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException("expected service error")));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(createSessionJson(PRINCIPAL, null, null)))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
    }
  }

  @ParameterizedTest
  @MethodSource
  void createSessionSuccess(final String pushToken, final String pushTokenType,
      final List<VerificationSession.Information> expectedRequestedInformation) {
    when(registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any()))
        .thenReturn(
            CompletableFuture.completedFuture(
                new RegistrationServiceSession(SESSION_ID, PRINCIPAL, false, null, null, null,
                    SESSION_EXPIRATION_SECONDS)));
    when(verificationSessionManager.insert(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(createSessionJson(PRINCIPAL, pushToken, pushTokenType)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);
      assertEquals(expectedRequestedInformation, verificationSessionResponse.requestedInformation());
      // FLT(uoemai): In the Flatline prototype, the client is currently always allowed to request a code.
      //              This may change once verification is migrated away from phone numbers.
      // assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertFalse(verificationSessionResponse.verified());
    }
  }

  static Stream<Arguments> createSessionSuccess() {
    return Stream.of(
        // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
        // Arguments.of(null, null, List.of(VerificationSession.Information.CAPTCHA)),
        // Arguments.of("token", "fcm",
        //   List.of(VerificationSession.Information.PUSH_CHALLENGE, VerificationSession.Information.CAPTCHA))
        Arguments.of(null, null, List.of()),
        Arguments.of("token", "fcm", List.of())
    );
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void createSessionReregistration(final boolean isReregistration) throws NumberParseException {
    when(registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any()))
        .thenReturn(
            CompletableFuture.completedFuture(
                new RegistrationServiceSession(SESSION_ID, PRINCIPAL, false, null, null, null,
                    SESSION_EXPIRATION_SECONDS)));

    when(verificationSessionManager.insert(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    when(accountsManager.getByPrincipal(PRINCIPAL))
        .thenReturn(isReregistration ? Optional.of(mock(Account.class)) : Optional.empty());

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");

    try (final Response response = request.post(Entity.json(createSessionJson(PRINCIPAL, null, null)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      verify(registrationServiceClient).createRegistrationSession(
          // FLT(uoemai): Pending the migration to OIDC registration, the principal is assumed to be a phone number.
          //              TODO: Migrate tests to use generic principals once registration is migrated to OIDC.
          eq(PhoneNumberUtil.getInstance().parse(PRINCIPAL, null)),
          anyString(),
          eq(isReregistration),
          any()
      );
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
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request().property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json("{}"))) {
      assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatus());
    }
  }

  @Test
  void patchSessionPushToken() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                new VerificationSession(null, List.of(VerificationSession.Information.CAPTCHA), Collections.emptyList(),
                    null, null, false, clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(null, null, "abcde", "fcm")))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final ArgumentCaptor<VerificationSession> verificationSessionArgumentCaptor = ArgumentCaptor.forClass(
          VerificationSession.class);
      verify(verificationSessionManager).update(any(), verificationSessionArgumentCaptor.capture());

      final VerificationSession updatedSession = verificationSessionArgumentCaptor.getValue();
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(VerificationSession.Information.PUSH_CHALLENGE, VerificationSession.Information.CAPTCHA),
      //          updatedSession.requestedInformation());
      // assertTrue(updatedSession.submittedInformation().isEmpty());
      assertEquals(List.of(), updatedSession.requestedInformation());
      assertNull(updatedSession.submittedInformation());
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertNotNull(updatedSession.pushChallenge());
      assertNull(updatedSession.pushChallenge());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      // FLT(uoemai): In the Flatline prototype, the client is currently always allowed to request a code.
      //              This may change once verification is migrated away from phone numbers.
      // assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.allowedToRequestCode());
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(VerificationSession.Information.PUSH_CHALLENGE),
      assertEquals(null, updatedSession.submittedInformation());
    }
  }

  @Test
  void patchSessionCaptchaRateLimited() throws Exception {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, false,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    doThrow(RateLimitExceededException.class)
        .when(captchaLimiter).validate(anyString());

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson("captcha", null, null, null)))) {
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      //              For this same reason, the verification captcha does not hit a rate limit.
      // assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, response.getStatus());
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      // FLT(uoemai): In the Flatline prototype, the client is currently always allowed to request a code.
      //              This may change once verification is migrated away from phone numbers.
      // assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void patchSessionPushChallengeRateLimited() throws Exception {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, false,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    doThrow(RateLimitExceededException.class)
        .when(pushChallengeLimiter).validate(anyString());

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(null, "challenge", null, null)))) {
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      //              For this same reason, the verification push challenge does not hit a rate limit.
      // assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, response.getStatus());
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      // FLT(uoemai): In the Flatline prototype, the client is currently always allowed to request a code.
      //              This may change once verification is migrated away from phone numbers.
      // assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void patchSessionPushChallengeMismatch() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession("challenge", List.of(VerificationSession.Information.PUSH_CHALLENGE),
                Collections.emptyList(), null, null, false, clock.millis(), clock.millis(),
                registrationServiceSession.expiration()))));
    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(null, "mismatched", null, null)))) {
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      //              For this same reason, the provided push challenge is not verified.
      // assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatus());
      assertEquals(HttpStatus.SC_OK, response.getStatus());


      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      // FLT(uoemai): In the Flatline prototype, the client is currently always allowed to request a code.
      //              This may change once verification is migrated away from phone numbers.
      // assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.allowedToRequestCode());
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(
      //    VerificationSession.Information.PUSH_CHALLENGE), verificationSessionResponse.requestedInformation());
      assertEquals(List.of(), verificationSessionResponse.requestedInformation());
    }
  }

  @Test
  void patchSessionCaptchaInvalid() throws Exception {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, List.of(VerificationSession.Information.CAPTCHA),
                Collections.emptyList(), null, null, false, clock.millis(), clock.millis(),
                registrationServiceSession.expiration()))));

    when(registrationCaptchaManager.assessCaptcha(any(), any(), any(), any()))
        .thenReturn(Optional.of(AssessmentResult.invalid()));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson("captcha", null, null, null)))) {
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      //              For this same reason, the provided captcha is not verified.
      // assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatus());

      final ArgumentCaptor<VerificationSession> verificationSessionArgumentCaptor = ArgumentCaptor.forClass(
          VerificationSession.class);

      verify(verificationSessionManager).update(any(), verificationSessionArgumentCaptor.capture());

      final VerificationSession updatedSession = verificationSessionArgumentCaptor.getValue();
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(VerificationSession.Information.CAPTCHA),
      //     updatedSession.requestedInformation());
      assertEquals(List.of(), updatedSession.requestedInformation());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      // FLT(uoemai): In the Flatline prototype, the client is currently always allowed to request a code.
      //              This may change once verification is migrated away from phone numbers.
      // assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.allowedToRequestCode());
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(
      //     VerificationSession.Information.CAPTCHA), verificationSessionResponse.requestedInformation());
      assertEquals(List.of(), verificationSessionResponse.requestedInformation());
    }
  }

  @Test
  void patchSessionPushChallengeAlreadySubmitted() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession("challenge",
                List.of(VerificationSession.Information.CAPTCHA),
                List.of(VerificationSession.Information.PUSH_CHALLENGE),
                null, null, false,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));
    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(null, "challenge", null, null)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final ArgumentCaptor<VerificationSession> verificationSessionArgumentCaptor = ArgumentCaptor.forClass(
          VerificationSession.class);

      verify(verificationSessionManager).update(any(), verificationSessionArgumentCaptor.capture());

      final VerificationSession updatedSession = verificationSessionArgumentCaptor.getValue();
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(VerificationSession.Information.PUSH_CHALLENGE),
      //     updatedSession.submittedInformation());
      // assertEquals(List.of(VerificationSession.Information.CAPTCHA), updatedSession.requestedInformation());
      assertNull(updatedSession.submittedInformation());
      assertEquals(List.of(), updatedSession.requestedInformation());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      // FLT(uoemai): In the Flatline prototype, the client is currently always allowed to request a code.
      //              This may change once verification is migrated away from phone numbers.
      // assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.allowedToRequestCode());
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(
      //     VerificationSession.Information.CAPTCHA), verificationSessionResponse.requestedInformation());
      assertEquals(List.of(), verificationSessionResponse.requestedInformation());
    }
  }

  @Test
  void patchSessionAlreadyVerified() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        true, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession("challenge", List.of(), List.of(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(null, "challenge", null, null)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.verified());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());

      verify(registrationRecoveryPasswordsManager).remove(PNI);
    }
  }

  @Test
  void patchSessionPushChallengeSuccess() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession("challenge",
                List.of(VerificationSession.Information.PUSH_CHALLENGE, VerificationSession.Information.CAPTCHA),
                Collections.emptyList(), null, null, false, clock.millis(), clock.millis(),
                registrationServiceSession.expiration()))));
    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson(null, "challenge", null, null)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final ArgumentCaptor<VerificationSession> verificationSessionArgumentCaptor = ArgumentCaptor.forClass(
          VerificationSession.class);

      verify(verificationSessionManager).update(any(), verificationSessionArgumentCaptor.capture());

      final VerificationSession updatedSession = verificationSessionArgumentCaptor.getValue();
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(VerificationSession.Information.PUSH_CHALLENGE),
      //     updatedSession.submittedInformation());
      assertNull(updatedSession.submittedInformation());
      assertTrue(updatedSession.requestedInformation().isEmpty());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void patchSessionCaptchaSuccess() throws Exception {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, List.of(VerificationSession.Information.CAPTCHA),
                Collections.emptyList(), null, null, false, clock.millis(), clock.millis(),
                registrationServiceSession.expiration()))));

    when(registrationCaptchaManager.assessCaptcha(any(), any(), any(), any()))
        .thenReturn(Optional.of(AssessmentResult.alwaysValid()));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH", Entity.json(updateSessionJson("captcha", null, null, null)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final ArgumentCaptor<VerificationSession> verificationSessionArgumentCaptor = ArgumentCaptor.forClass(
          VerificationSession.class);

      verify(verificationSessionManager).update(any(), verificationSessionArgumentCaptor.capture());

      final VerificationSession updatedSession = verificationSessionArgumentCaptor.getValue();
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(VerificationSession.Information.PUSH_CHALLENGE),
      //     updatedSession.submittedInformation());
      assertEquals(null, updatedSession.submittedInformation());
      assertTrue(updatedSession.requestedInformation().isEmpty());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void patchSessionPushAndCaptchaSuccess() throws Exception {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession("challenge",
                List.of(VerificationSession.Information.CAPTCHA, VerificationSession.Information.CAPTCHA),
                Collections.emptyList(), null, null, false, clock.millis(), clock.millis(),
                registrationServiceSession.expiration()))));

    when(registrationCaptchaManager.assessCaptcha(any(), any(), any(), any()))
        .thenReturn(Optional.of(AssessmentResult.alwaysValid()));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH",
        Entity.json(updateSessionJson("captcha", "challenge", null, null)))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final ArgumentCaptor<VerificationSession> verificationSessionArgumentCaptor = ArgumentCaptor.forClass(
          VerificationSession.class);

      verify(verificationSessionManager).update(any(), verificationSessionArgumentCaptor.capture());

      final VerificationSession updatedSession = verificationSessionArgumentCaptor.getValue();
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertEquals(List.of(VerificationSession.Information.PUSH_CHALLENGE, VerificationSession.Information.CAPTCHA),
      //     updatedSession.submittedInformation());
      assertNull(updatedSession.submittedInformation());
      assertTrue(updatedSession.requestedInformation().isEmpty());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void patchSessionTokenUpdatedCaptchaError() throws Exception {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null,
                List.of(VerificationSession.Information.CAPTCHA),
                Collections.emptyList(), null, null, false, clock.millis(), clock.millis(),
                registrationServiceSession.expiration()))));

    when(registrationCaptchaManager.assessCaptcha(any(), any(), any(), any()))
        .thenThrow(new IOException("expected service error"));

    when(verificationSessionManager.update(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.method("PATCH",
        Entity.json(updateSessionJson("captcha", null, "token", "fcm")))) {
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      //              For this reason, the captcha cannot fail to be verified.
      // assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, response.getStatus());
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final ArgumentCaptor<VerificationSession> verificationSessionArgumentCaptor = ArgumentCaptor.forClass(
          VerificationSession.class);

      verify(verificationSessionManager).update(any(), verificationSessionArgumentCaptor.capture());

      final VerificationSession updatedSession = verificationSessionArgumentCaptor.getValue();
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertTrue(updatedSession.submittedInformation().isEmpty());
      // assertEquals(List.of(VerificationSession.Information.PUSH_CHALLENGE, VerificationSession.Information.CAPTCHA),
      //          updatedSession.requestedInformation());
      assertNull(updatedSession.submittedInformation());
      assertEquals(List.of(), updatedSession.requestedInformation());
      // FLT(uoemai): In the Flatline prototype, there are currently no verification challenges.
      // assertNotNull(updatedSession.pushChallenge());
      assertNull(updatedSession.pushChallenge());
    }
  }

  @Test
  void getSessionMalformedId() {
    final String invalidSessionId = "()()()";

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + invalidSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_UNPROCESSABLE_ENTITY, response.getStatus());
    }
  }

  @Test
  void getSessionInvalidArgs() {
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.failedFuture(new StatusRuntimeException(Status.INVALID_ARGUMENT)));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatus());
    }
  }

  @Test
  void getSessionNotFound() {
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));
    when(verificationSessionManager.findForId(encodeSessionId(SESSION_ID)))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatus());
    }

    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                new RegistrationServiceSession(SESSION_ID, PRINCIPAL, false, null, null, null,
                    SESSION_EXPIRATION_SECONDS))));

    request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatus());
    }
  }

  @Test
  void getSessionError() {
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException()));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodeSessionId(SESSION_ID))
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, response.getStatus());
    }
  }

  @Test
  void getSessionSuccess() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                new RegistrationServiceSession(SESSION_ID, PRINCIPAL, false, null, null, null,
                    SESSION_EXPIRATION_SECONDS))));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(mock(VerificationSession.class))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());
    }
  }

  @Test
  void getSessionSuccessAlreadyVerified() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        true, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(mock(VerificationSession.class))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId)
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.get()) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      verify(registrationRecoveryPasswordsManager).remove(PNI);
    }
  }

  @Test
  void requestVerificationCodeAlreadyVerified() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        true, null, null,
        null, SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));
    when(registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
        .thenReturn(CompletableFuture.completedFuture(registrationServiceSession));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(requestVerificationCodeJson("sms", "android")))) {
      assertEquals(HttpStatus.SC_CONFLICT, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.verified());
    }
  }

  @Test
  void requestVerificationCodeNotAllowedInformationRequested() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(new VerificationSession(null, List.of(
            VerificationSession.Information.CAPTCHA), Collections.emptyList(), null, null, false, clock.millis(), clock.millis(),
            registrationServiceSession.expiration()))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(requestVerificationCodeJson("sms", "ios")))) {
      assertEquals(HttpStatus.SC_CONFLICT, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertEquals(List.of(VerificationSession.Information.CAPTCHA),
          verificationSessionResponse.requestedInformation());
    }
  }

  @Test
  void requestVerificationCodeNotAllowed() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, null,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(
                registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, false,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(requestVerificationCodeJson("voice", "android")))) {
      assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertFalse(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void requestVerificationCodeRateLimitExceeded() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null,
        null, SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));
    when(registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
        .thenReturn(CompletableFuture.failedFuture(
            new CompletionException(new VerificationSessionRateLimitExceededException(registrationServiceSession,
                Duration.ofMinutes(1), true))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(requestVerificationCodeJson("sms", "android")))) {
      assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void requestVerificationCodeTransportNotAllowed() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null,
        null, SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));
    when(registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
        .thenReturn(CompletableFuture.failedFuture(
            new CompletionException(new TransportNotAllowedException(registrationServiceSession))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");

    try (final Response response = request.post(Entity.json(requestVerificationCodeJson("sms", "android")))) {
      assertEquals(418, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse =
          response.readEntity(CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void requestVerificationCodeSuccess() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null,
        null, SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));
    when(registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
        .thenReturn(CompletableFuture.completedFuture(registrationServiceSession));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(requestVerificationCodeJson("sms", "android")))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @ParameterizedTest
  @MethodSource
  void requestVerificationCodeExternalServiceRefused(final boolean expectedPermanent, final String expectedReason,
      final RegistrationServiceSenderException exception) {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
        .thenReturn(
            CompletableFuture.failedFuture(new CompletionException(exception)));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(requestVerificationCodeJson("voice", "ios")))) {
      assertEquals(RegistrationServiceSenderExceptionMapper.REMOTE_SERVICE_REJECTED_REQUEST_STATUS, response.getStatus());

      final Map<String, Object> responseMap = response.readEntity(Map.class);

      assertEquals(expectedReason, responseMap.get("reason"));
      assertEquals(expectedPermanent, responseMap.get("permanentFailure"));
    }
  }

  static Stream<Arguments> requestVerificationCodeExternalServiceRefused() {
    return Stream.of(
        Arguments.of(true, "illegalArgument", RegistrationServiceSenderException.illegalArgument(true)),
        Arguments.of(true, "providerRejected", RegistrationServiceSenderException.rejected(true)),
        Arguments.of(false, "providerUnavailable", RegistrationServiceSenderException.unknown(false))
    );
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void fraudError(boolean shadowFailure) {
    if (shadowFailure) {
      when(this.dynamicConfiguration.getRegistrationConfiguration())
          .thenReturn(new DynamicRegistrationConfiguration(true));
    }
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
        .thenReturn(CompletableFuture.failedFuture(new CompletionException(
            new RegistrationFraudException(RegistrationServiceSenderException.rejected(true)))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.post(Entity.json(requestVerificationCodeJson("voice", "ios")))) {
      if (shadowFailure) {
        assertEquals(200, response.getStatus());
      } else {
        assertEquals(RegistrationServiceSenderExceptionMapper.REMOTE_SERVICE_REJECTED_REQUEST_STATUS, response.getStatus());
        final Map<String, Object> responseMap = response.readEntity(Map.class);
        assertEquals("providerRejected", responseMap.get("reason"));
      }
    }
  }


  @Test
  void verifyCodeServerError() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(registrationServiceClient.checkVerificationCode(any(), any(), any()))
        .thenReturn(CompletableFuture.failedFuture(new CompletionException(new RuntimeException())));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.put(Entity.json(submitVerificationCodeJson("123456")))) {
      assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatus());
    }
  }

  @Test
  void verifyCodeAlreadyVerified() {

    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        true, null, null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.put(
        Entity.json(submitVerificationCodeJson("123456")))) {

      verify(registrationServiceClient).getSession(any(), any());
      verifyNoMoreInteractions(registrationServiceClient);

      assertEquals(HttpStatus.SC_CONFLICT, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);
      assertTrue(verificationSessionResponse.verified());

      verify(registrationRecoveryPasswordsManager).remove(PNI);
    }
  }

  @Test
  void verifyCodeNoCodeRequested() {

    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, 0L, null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    // There is no explicit indication in the exception that no code has been sent, but we treat all RegistrationServiceExceptions
    // in which the response has a session object as conflicted state
    when(registrationServiceClient.checkVerificationCode(any(), any(), any()))
        .thenReturn(CompletableFuture.failedFuture(new CompletionException(
            new RegistrationServiceException(new RegistrationServiceSession(SESSION_ID, PRINCIPAL, false, 0L, null, null,
                SESSION_EXPIRATION_SECONDS)))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.put(Entity.json(submitVerificationCodeJson("123456")))) {
      assertEquals(HttpStatus.SC_CONFLICT, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertNotNull(verificationSessionResponse.nextSms());
      assertNull(verificationSessionResponse.nextVerificationAttempt());
    }
  }

  @Test
  void verifyCodeNoSession() {

    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    when(registrationServiceClient.checkVerificationCode(any(), any(), any()))
        .thenReturn(CompletableFuture.failedFuture(new CompletionException(new RegistrationServiceException(null))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.put(Entity.json(submitVerificationCodeJson("123456")))) {
      assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatus());
    }
  }

  @Test
  void verifyCodeRateLimitExceeded() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));
    when(registrationServiceClient.checkVerificationCode(any(), any(), any()))
        .thenReturn(CompletableFuture.failedFuture(
            new CompletionException(new VerificationSessionRateLimitExceededException(registrationServiceSession,
                Duration.ofMinutes(1), true))));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.put(Entity.json(submitVerificationCodeJson("567890")))) {
      assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.allowedToRequestCode());
      assertTrue(verificationSessionResponse.requestedInformation().isEmpty());
    }
  }

  @Test
  void verifyCodeSuccess() {
    final String encodedSessionId = encodeSessionId(SESSION_ID);
    final RegistrationServiceSession registrationServiceSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL,
        false, null, null, 0L, SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.getSession(any(), any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(registrationServiceSession)));
    when(verificationSessionManager.findForId(any()))
        .thenReturn(CompletableFuture.completedFuture(
            Optional.of(new VerificationSession(null, Collections.emptyList(), Collections.emptyList(), null, null, true,
                clock.millis(), clock.millis(), registrationServiceSession.expiration()))));

    final RegistrationServiceSession verifiedSession = new RegistrationServiceSession(SESSION_ID, PRINCIPAL, true, null,
        null, 0L,
        SESSION_EXPIRATION_SECONDS);
    when(registrationServiceClient.checkVerificationCode(any(), any(), any()))
        .thenReturn(CompletableFuture.completedFuture(verifiedSession));

    final Invocation.Builder request = resources.getJerseyTest()
        .target("/v1/verification/session/" + encodedSessionId + "/code")
        .request()
        .header(HttpHeaders.X_FORWARDED_FOR, "127.0.0.1");
    try (Response response = request.put(Entity.json(submitVerificationCodeJson("123456")))) {
      assertEquals(HttpStatus.SC_OK, response.getStatus());

      final CreateVerificationSessionResponse verificationSessionResponse = response.readEntity(
          CreateVerificationSessionResponse.class);

      assertTrue(verificationSessionResponse.verified());

      verify(registrationRecoveryPasswordsManager).remove(PNI);
    }
  }

  /**
   * Request JSON in the shape of {@link org.whispersystems.textsecuregcm.entities.CreateVerificationSessionRequest}
   */
  private static String createSessionJson(final String principal, final String pushToken,
      final String pushTokenType) {
    return String.format("""
        {
          "principal": %s,
          "pushToken": %s,
          "pushTokenType": %s
        }
        """, quoteIfNotNull(principal), quoteIfNotNull(pushToken), quoteIfNotNull(pushTokenType));
  }

  /**
   * Request JSON in the shape of {@link org.whispersystems.textsecuregcm.entities.UpdateVerificationSessionRequest}
   */
  private static String updateSessionJson(final String captcha, final String pushChallenge, final String pushToken,
      final String pushTokenType) {
    return String.format("""
            {
              "captcha": %s,
              "pushChallenge": %s,
              "pushToken": %s,
              "pushTokenType": %s
            }
            """, quoteIfNotNull(captcha), quoteIfNotNull(pushChallenge), quoteIfNotNull(pushToken),
        quoteIfNotNull(pushTokenType));
  }

  /**
   * Request JSON in the shape of {@link org.whispersystems.textsecuregcm.entities.VerificationCodeRequest}
   */
  private static String requestVerificationCodeJson(final String transport, final String client) {
    return String.format("""
             {
               "transport": "%s",
               "client": "%s"
             }
        """, transport, client);
  }

  /**
   * Request JSON in the shape of {@link org.whispersystems.textsecuregcm.entities.SubmitVerificationCodeRequest}
   */
  private static String submitVerificationCodeJson(final String code) {
    return String.format("""
        {
          "code": "%s"
        }
        """, code);
  }

  private static String quoteIfNotNull(final String s) {
    return s == null ? null : StringUtils.join(new String[]{"\"", "\""}, s);
  }

  /**
   * Request JSON that cannot be marshalled into
   * {@link org.whispersystems.textsecuregcm.entities.CreateVerificationSessionRequest}
   */
  private static String unprocessableCreateSessionJson(final String principal, final String pushToken,
      final String pushTokenType) {
    return String.format("""
        {
          "principal": %s,
          "pushToken": %s,
          "pushTokenType": %s
        }
        """, principal, quoteIfNotNull(pushToken), quoteIfNotNull(pushTokenType));
  }

  private static String encodeSessionId(final byte[] sessionId) {
    return Base64.getUrlEncoder().encodeToString(sessionId);
  }

}
