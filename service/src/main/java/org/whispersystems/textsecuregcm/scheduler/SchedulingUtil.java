package org.whispersystems.textsecuregcm.scheduler;

import com.google.common.annotations.VisibleForTesting;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Optional;
import io.micrometer.core.instrument.Metrics;
import org.whispersystems.textsecuregcm.metrics.MetricsUtil;
import org.whispersystems.textsecuregcm.storage.Account;

public class SchedulingUtil {
  private static final String PARSED_TIMEZONE_COUNTER_NAME = MetricsUtil.name(SchedulingUtil.class, "parsedTimezone");
  private static final String HAS_TIMEZONE_TAG_NAME = "hasTimezone";

  /**
   * Gets a present or future time at which to send a notification to a device associated with the given account. This
   * is mainly intended to facilitate scheduling notifications such that they arrive during a recipient's waking hours.
   * <p/>
   * FLT(uoemai): This method would previously attempt to use a timezone derived from the account's phone number to
   * choose an appropriate time to send a notification. If a timezone could be derived from the account's phone number,
   * then this method would default to the preferred time in the server's timezone. This later default is the only
   * behavior currently supported in Flatline.
   *
   * @param account the account that will receive the notification
   * @param preferredTime the preferred local time (e.g. "noon") at which to deliver the notification
   * @param clock a source of the current time
   *
   * @return the next time in the present or future at which to send a notification for the target account
   */
  public static Instant getNextRecommendedNotificationTime(final Account account,
      final LocalTime preferredTime,
      final Clock clock) {

    final ZonedDateTime candidateNotificationTime = getZoneId(account, clock)
        .map(zoneId -> {
          Metrics.counter(PARSED_TIMEZONE_COUNTER_NAME, HAS_TIMEZONE_TAG_NAME, String.valueOf(true)).increment();
          return ZonedDateTime.now(clock.withZone(zoneId)).with(preferredTime);
        })
        .orElseGet(() -> {
          Metrics.counter(PARSED_TIMEZONE_COUNTER_NAME, HAS_TIMEZONE_TAG_NAME, String.valueOf(false)).increment();
          return ZonedDateTime.now(ZoneId.systemDefault()).with(preferredTime);
        });

    if (candidateNotificationTime.toInstant().isBefore(clock.instant())) {
      // We've missed our opportunity today, so go for the same time tomorrow
      return candidateNotificationTime.plusDays(1).toInstant();
    } else {
      // The best time to send a notification hasn't happened yet today
      return candidateNotificationTime.toInstant();
    }
  }

  @VisibleForTesting
  static Optional<ZoneId> getZoneId(final Account account, final Clock clock) {
      // FLT(uoemai): This function used to return the time-zone based on the account phone number.
      //              With principals, this information can no longer be inferred.
      //              This function is kept in Flatline for compatibility purposes.
      return Optional.empty();
  }
}
