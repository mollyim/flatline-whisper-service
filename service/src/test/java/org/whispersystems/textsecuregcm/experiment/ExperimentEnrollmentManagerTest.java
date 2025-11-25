/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.experiment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicExperimentEnrollmentConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicPrincipalExperimentEnrollmentConfiguration;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;

class ExperimentEnrollmentManagerTest {

  private DynamicExperimentEnrollmentConfiguration.UuidSelector uuidSelector;
  private DynamicExperimentEnrollmentConfiguration experimentEnrollmentConfiguration;
  private DynamicPrincipalExperimentEnrollmentConfiguration principalExperimentEnrollmentConfiguration;

  private ExperimentEnrollmentManager experimentEnrollmentManager;

  private Account account;
  private Random random;

  private static final UUID ACCOUNT_UUID = UUID.randomUUID();
  private static final UUID EXCLUDED_UUID = UUID.randomUUID();
  private static final String UUID_EXPERIMENT_NAME = "uuid_test";
  private static final String PRINCIPAL_AND_UUID_EXPERIMENT_NAME = "principal_uuid_test";

  private static final String NOT_ENROLLED_PRINCIPAL = "not.enrolled.principal@example.com";
  private static final String ENROLLED_PRINCIPAL = "enrolled.principal@example.com";
  private static final String EXCLUDED_PRINCIPAL = "excluded.principal@example.com";
  private static final String PRINCIPAL_EXPERIMENT_NAME = "principal_test";

  @BeforeEach
  void setUp() {
    @SuppressWarnings("unchecked")
    final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager = mock(DynamicConfigurationManager.class);
    final DynamicConfiguration dynamicConfiguration = mock(DynamicConfiguration.class);
    random = spy(new Random());
    experimentEnrollmentManager = new ExperimentEnrollmentManager(dynamicConfigurationManager, () -> random);

    uuidSelector = mock(DynamicExperimentEnrollmentConfiguration.UuidSelector.class);
    when(uuidSelector.getUuidEnrollmentPercentage()).thenReturn(100);

    experimentEnrollmentConfiguration = mock(DynamicExperimentEnrollmentConfiguration.class);
    when(experimentEnrollmentConfiguration.getUuidSelector()).thenReturn(uuidSelector);
    principalExperimentEnrollmentConfiguration = mock(
        DynamicPrincipalExperimentEnrollmentConfiguration.class);

    when(dynamicConfigurationManager.getConfiguration()).thenReturn(dynamicConfiguration);
    when(dynamicConfiguration.getExperimentEnrollmentConfiguration(UUID_EXPERIMENT_NAME))
        .thenReturn(Optional.of(experimentEnrollmentConfiguration));
    when(dynamicConfiguration.getPrincipalExperimentEnrollmentConfiguration(PRINCIPAL_EXPERIMENT_NAME))
        .thenReturn(Optional.of(principalExperimentEnrollmentConfiguration));
    when(dynamicConfiguration.getExperimentEnrollmentConfiguration(PRINCIPAL_AND_UUID_EXPERIMENT_NAME))
        .thenReturn(Optional.of(experimentEnrollmentConfiguration));
    when(dynamicConfiguration.getPrincipalExperimentEnrollmentConfiguration(PRINCIPAL_AND_UUID_EXPERIMENT_NAME))
        .thenReturn(Optional.of(principalExperimentEnrollmentConfiguration));

    account = mock(Account.class);
    when(account.getUuid()).thenReturn(ACCOUNT_UUID);
  }

  @Test
  void testIsEnrolled_UuidExperiment() {
    assertFalse(experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME));
    assertFalse(
        experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME + "-unrelated-experiment"));

    when(uuidSelector.getUuids()).thenReturn(Set.of(ACCOUNT_UUID));
    assertTrue(experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME));

    when(uuidSelector.getUuids()).thenReturn(Collections.emptySet());
    when(experimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(0);

    assertFalse(experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME));

    when(experimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(100);
    assertTrue(experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME));

    when(experimentEnrollmentConfiguration.getExcludedUuids()).thenReturn(Set.of(EXCLUDED_UUID));
    when(experimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(100);
    when(uuidSelector.getUuidEnrollmentPercentage()).thenReturn(100);
    when(uuidSelector.getUuids()).thenReturn(Set.of(EXCLUDED_UUID));
    assertFalse(experimentEnrollmentManager.isEnrolled(EXCLUDED_UUID, UUID_EXPERIMENT_NAME));
  }

  @Test
  void testIsEnrolled_UuidExperimentPercentage() {
    when(uuidSelector.getUuids()).thenReturn(Set.of(ACCOUNT_UUID));
    when(uuidSelector.getUuidEnrollmentPercentage()).thenReturn(0);
    assertFalse(experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME));
    when(uuidSelector.getUuidEnrollmentPercentage()).thenReturn(100);
    assertTrue(experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME));

    when(uuidSelector.getUuidEnrollmentPercentage()).thenReturn(75);
    final Map<Boolean, Long> counts = IntStream.range(0, 100).mapToObj(i -> {
          when(random.nextInt(100)).thenReturn(i);
          return experimentEnrollmentManager.isEnrolled(account.getUuid(), UUID_EXPERIMENT_NAME);
        })
        .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));
    assertEquals(25, counts.get(false));
    assertEquals(75, counts.get(true));
  }

  @Test
  void testIsEnrolled_PrincipalAndUuidExperiment() {
    when(principalExperimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(0);
    when(principalExperimentEnrollmentConfiguration.getEnrolledPrincipals()).thenReturn(Collections.emptySet());
    when(principalExperimentEnrollmentConfiguration.getExcludedPrincipals()).thenReturn(Collections.emptySet());

    // test UUID enrollment is prioritized
    when(uuidSelector.getUuids()).thenReturn(Set.of(ACCOUNT_UUID));
    when(uuidSelector.getUuidEnrollmentPercentage()).thenReturn(100);
    assertTrue(experimentEnrollmentManager.isEnrolled(NOT_ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));
    when(uuidSelector.getUuidEnrollmentPercentage()).thenReturn(0);
    assertFalse(experimentEnrollmentManager.isEnrolled(NOT_ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));
    assertFalse(experimentEnrollmentManager.isEnrolled(ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));

    // test fallback from UUID enrollment to general enrollment percentage
    when(uuidSelector.getUuids()).thenReturn(Collections.emptySet());
    when(experimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(100);
    assertTrue(experimentEnrollmentManager.isEnrolled(NOT_ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));
    assertTrue(experimentEnrollmentManager.isEnrolled(ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));

    // test fallback from UUID/general enrollment to principal enrollment
    when(experimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(0);
    assertTrue(experimentEnrollmentManager.isEnrolled(ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));
    assertFalse(experimentEnrollmentManager.isEnrolled(NOT_ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));
    when(principalExperimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(100);
    assertTrue(experimentEnrollmentManager.isEnrolled(ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));
    assertTrue(experimentEnrollmentManager.isEnrolled(NOT_ENROLLED_PRINCIPAL, account.getUuid(), PRINCIPAL_AND_UUID_EXPERIMENT_NAME));
  }

  @ParameterizedTest
  @MethodSource
  void testIsEnrolled_PrincipalExperiment(final String principal, final String experimentName,
      final Set<String> enrolledPrincipals, final Set<String> excludedPrincipals,
      final int enrollmentPercentage,
      final boolean expectEnrolled, final String message) {

    when(principalExperimentEnrollmentConfiguration.getEnrolledPrincipals()).thenReturn(enrolledPrincipals);
    when(principalExperimentEnrollmentConfiguration.getExcludedPrincipals()).thenReturn(excludedPrincipals);
    when(principalExperimentEnrollmentConfiguration.getEnrollmentPercentage()).thenReturn(enrollmentPercentage);

    assertEquals(expectEnrolled, experimentEnrollmentManager.isEnrolled(principal, experimentName), message);
  }

  static Stream<Arguments> testIsEnrolled_PrincipalExperiment() {
    return Stream.of(
        Arguments.of(ENROLLED_PRINCIPAL, PRINCIPAL_EXPERIMENT_NAME, Collections.emptySet(), Collections.emptySet(),
            0, false, "default configuration expects no enrollment"),
        Arguments.of(ENROLLED_PRINCIPAL, PRINCIPAL_EXPERIMENT_NAME + "-unrelated-experiment", Collections.emptySet(), Collections.emptySet(),
            0, false, "unknown experiment expects no enrollment"),
        Arguments.of(ENROLLED_PRINCIPAL, PRINCIPAL_EXPERIMENT_NAME, Set.of(ENROLLED_PRINCIPAL), Set.of(EXCLUDED_PRINCIPAL),
            0, true, "explicitly enrolled principal overrides 0% rollout"),
        Arguments.of(EXCLUDED_PRINCIPAL, PRINCIPAL_EXPERIMENT_NAME, Collections.emptySet(), Set.of(EXCLUDED_PRINCIPAL),
            100, false, "excluded principal overrides 100% rollout"),
        Arguments.of(ENROLLED_PRINCIPAL, PRINCIPAL_EXPERIMENT_NAME, Collections.emptySet(), Collections.emptySet(),
            100, true, "enrollment expected for 100% rollout")
    );
  }
}
