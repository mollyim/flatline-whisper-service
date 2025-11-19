/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.experiment;

import com.google.common.annotations.VisibleForTesting;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicExperimentEnrollmentConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicPrincipalExperimentEnrollmentConfiguration;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;

public class ExperimentEnrollmentManager {

  private final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager;
  private final Supplier<Random> random;


  public ExperimentEnrollmentManager(
      final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager) {
    this(dynamicConfigurationManager, ThreadLocalRandom::current);
  }

  @VisibleForTesting
  ExperimentEnrollmentManager(
      final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager,
      final Supplier<Random> random) {
    this.dynamicConfigurationManager = dynamicConfigurationManager;
    this.random = random;
  }

  public boolean isEnrolled(final UUID accountUuid, final String experimentName) {

    final Optional<DynamicExperimentEnrollmentConfiguration> maybeConfiguration = dynamicConfigurationManager
        .getConfiguration().getExperimentEnrollmentConfiguration(experimentName);

    return maybeConfiguration
        .map(config -> isAccountEnrolled(accountUuid, config, experimentName).orElse(false))
        .orElse(false);
  }

  private Optional<Boolean> isAccountEnrolled(final UUID accountUuid, DynamicExperimentEnrollmentConfiguration config, String experimentName) {
    if (config.getExcludedUuids().contains(accountUuid)) {
      return Optional.of(false);
    }
    if (config.getUuidSelector().getUuids().contains(accountUuid)) {
      final int r = random.get().nextInt(100);
      return Optional.of(r < config.getUuidSelector().getUuidEnrollmentPercentage());
    }

    if (isEnrolled(accountUuid, config.getEnrollmentPercentage(), experimentName)) {
      return Optional.of(true);
    }

    return Optional.empty();
  }

  public boolean isEnrolled(final String principal, final UUID accountUuid, final String experimentName) {

    final Optional<DynamicExperimentEnrollmentConfiguration> maybeConfiguration = dynamicConfigurationManager
        .getConfiguration().getExperimentEnrollmentConfiguration(experimentName);

    return maybeConfiguration
        .flatMap(config -> isAccountEnrolled(accountUuid, config, experimentName))
        .orElse(isEnrolled(principal, experimentName));
  }

  public boolean isEnrolled(final String principal, final String experimentName) {

    final Optional<DynamicPrincipalExperimentEnrollmentConfiguration> maybeConfiguration = dynamicConfigurationManager
        .getConfiguration().getPrincipalExperimentEnrollmentConfiguration(experimentName);

    return maybeConfiguration.map(config -> {

      if (config.getEnrolledPrincipals().contains(principal)) {
        return true;
      }

      if (config.getExcludedPrincipals().contains(principal)) {
        return false;
      }

      // FLT(uoemai): Here, it was possible to enroll accounts by country code.
      // In Flatline, there is no guarantee that the principal will contain country information.
      // A similar effect could be achieved by enrolling based on principal prefixes or suffixes.

      return isEnrolled(principal, config.getEnrollmentPercentage(), experimentName);

    }).orElse(false);
  }

  private boolean isEnrolled(final Object entity, final int enrollmentPercentage, final String experimentName) {
    final int enrollmentHash = ((entity.hashCode() ^ experimentName.hashCode()) & Integer.MAX_VALUE) % 100;

    return enrollmentHash < enrollmentPercentage;
  }
}
