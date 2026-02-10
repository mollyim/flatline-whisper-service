package org.whispersystems.textsecuregcm.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.storage.Account;

class SchedulingUtilTest {

  @Test
  void getNextRecommendedNotificationTime() {
    {
      final Account account = mock(Account.class);

      // FLT(uoemai): The account principal cannot be connected to a region or time-zone.
      when(account.getPrincipal()).thenReturn("user.account@example.com");

      final ZonedDateTime beforeNotificationTime = ZonedDateTime.now(ZoneId.systemDefault()).with(LocalTime.of(13, 59));
      final LocalTime preferredNotificationTime = LocalTime.of(14, 0);

      assertEquals(
          beforeNotificationTime.with(preferredNotificationTime).toInstant(),
          SchedulingUtil.getNextRecommendedNotificationTime(account, preferredNotificationTime,
              Clock.fixed(beforeNotificationTime.toInstant(), ZoneId.systemDefault())));

      final ZonedDateTime afterNotificationTime = ZonedDateTime.now(ZoneId.systemDefault()).with(LocalTime.of(14, 1));

      assertEquals(
          afterNotificationTime.with(preferredNotificationTime).plusDays(1).toInstant(),
          SchedulingUtil.getNextRecommendedNotificationTime(account, preferredNotificationTime,
              Clock.fixed(afterNotificationTime.toInstant(), ZoneId.systemDefault())));
    }
  }

  @Test
  void getNextRecommendedNotificationTimeDaylightSavings() {
    // FLT(uoemai): In Flatline, there is currently no knowledge of the time zone for an account.
    //              Previously, this would be the case, as that would be inferred from the phone number country code.
    //              This test is kept to document this change and keep the option open for the future.
  }

  @Test
  void zoneIdSelectionSingleOffset() {
    // FLT(uoemai): In Flatline, there is currently no knowledge of the time zone for an account.
    //              Previously, this would be the case, as that would be inferred from the phone number country code.
    //              This test is kept to document this change and keep the option open for the future.
  }

  @Test
  void zoneIdSelectionMultipleOffsets() {
    // FLT(uoemai): In Flatline, there is currently no knowledge of the time zone for an account.
    //              Previously, this would be the case, as that would be inferred from the phone number country code.
    //              This test is kept to document this change and keep the option open for the future.
  }
}
