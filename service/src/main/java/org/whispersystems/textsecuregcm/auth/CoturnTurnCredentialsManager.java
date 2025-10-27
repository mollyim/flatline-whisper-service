/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import io.netty.resolver.dns.DnsNameResolver;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.HmacUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.net.Inet6Address;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

// FLT(uoemai): This class generates credentials for Coturn, which replaces Cloudflare in Flatline.
// Unlike with Cloudflare, these credentials are generated completely in Whisper using a shared secret.
// See more: https://github.com/coturn/coturn/wiki/turnserver#turn-rest-api
public class CoturnTurnCredentialsManager {

  private static final Logger logger = LoggerFactory.getLogger(CoturnTurnCredentialsManager.class);

  private final String coturnTurnSecret;
  private final List<String> coturnTurnUrls;
  private final List<String> coturnTurnUrlsWithIps;
  private final String coturnTurnHostname;

  private final DnsNameResolver dnsNameResolver;

  private final Duration credentialTtl;
  private final Duration clientCredentialTtl;

  public CoturnTurnCredentialsManager(final String coturnTurnSecret,
                                      final Duration credentialTtl,
                                      final Duration clientCredentialTtl,
                                      final List<String> coturnTurnUrls,
                                      final List<String> coturnTurnUrlsWithIps,
                                      final String coturnTurnHostname,
                                      final DnsNameResolver dnsNameResolver) {

    this.coturnTurnSecret = coturnTurnSecret;
    this.credentialTtl = credentialTtl;
    this.clientCredentialTtl = clientCredentialTtl;
    this.coturnTurnUrls = coturnTurnUrls;
    this.coturnTurnUrlsWithIps = coturnTurnUrlsWithIps;
    this.coturnTurnHostname = coturnTurnHostname;
    this.dnsNameResolver = dnsNameResolver;
  }

  public TurnToken generateForCoturn() throws IOException {
    final List<String> coturnTurnComposedUrls;
    try {
      coturnTurnComposedUrls = dnsNameResolver.resolveAll(coturnTurnHostname).get().stream()
          .map(i -> switch (i) {
            case Inet6Address i6 -> "[" + i6.getHostAddress() + "]";
            default -> i.getHostAddress();
          })
          .flatMap(i -> coturnTurnUrlsWithIps.stream().map(u -> u.formatted(i)))
          .toList();
    } catch (Exception e) {
      throw new IOException(e);
    }

    String username = UUID.randomUUID().toString();
    long timestamp = Instant.now().getEpochSecond() + credentialTtl.getSeconds();
    String coturnTurnUser = timestamp + ":" + username;
    logger.warn("Using user: {}", coturnTurnUser);
    byte[] key = coturnTurnSecret.getBytes(StandardCharsets.UTF_8);
    HmacUtils mac = new HmacUtils("HmacSHA1", key);
    String coturnTurnPassword = Base64.encodeBase64String(mac.hmac(coturnTurnUser));
    logger.warn("Using password: {}", coturnTurnPassword);

    return new TurnToken(
        coturnTurnUser,
        coturnTurnPassword,
        clientCredentialTtl.toSeconds(),
        coturnTurnUrls == null ? Collections.emptyList() : coturnTurnUrls,
        coturnTurnComposedUrls,
        coturnTurnHostname
    );
  }
}
