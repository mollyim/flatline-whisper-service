/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.push;

import org.apache.commons.lang3.StringUtils;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.Device;
import javax.annotation.Nullable;

public record PushNotification(PushToken<?> pushToken,
                               NotificationType notificationType,
                               @Nullable String data,
                               @Nullable Account destination,
                               @Nullable Device destinationDevice,
                               boolean urgent) {

  static public class UnsupportedNotificationType extends Exception{
    public UnsupportedNotificationType(NotificationType type) {
      super("Unsupported push type: " + type.name());
    }
  }

  public enum NotificationType {
    NOTIFICATION,
    ATTEMPT_LOGIN_NOTIFICATION_HIGH_PRIORITY,
    CHALLENGE,
    ACTIVATION_TOKEN,
    RATE_LIMIT_CHALLENGE
  }

  public enum TokenType {
    WEBPUSH,
    FCM,
    APN
  }

  public sealed interface PushToken<T> permits PushToken.FCM, PushToken.APN, PushToken.WEBPUSH {
    T value();
    TokenType type();

    default boolean isBlank() {
      if (value() == null) return true;
      return switch(value()) {
        case String s -> StringUtils.isBlank(s);
        default -> false;
      };
    }

    public record FCM(String value) implements PushToken<String> {
      public TokenType type() { return TokenType.FCM; }
    }
    public record APN(String value) implements PushToken<String> {
      public TokenType type() { return TokenType.APN; }
    }
    public record WEBPUSH(WebPushSubscription value, boolean activated) implements PushToken<WebPushSubscription> {
      public TokenType type() { return TokenType.WEBPUSH; }
    }
  }

  public TokenType tokenType() {
    return pushToken().type();
  }
}
