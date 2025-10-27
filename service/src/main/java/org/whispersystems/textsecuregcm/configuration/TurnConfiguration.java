/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;
// FLT(uoemai): The Flatline prototype uses Coturn as a self-hosted replacement for Cloudflare.
// public record TurnConfiguration(CloudflareTurnConfiguration cloudflare) {
public record TurnConfiguration(CoturnTurnConfiguration coturn) {
}
