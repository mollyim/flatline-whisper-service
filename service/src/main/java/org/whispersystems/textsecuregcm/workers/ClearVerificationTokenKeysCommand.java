/*
 * Copyright 2013 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.workers;

import com.nimbusds.jose.jwk.JWKSet;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Environment;
import java.util.Optional;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.storage.VerificationTokenKeysManager;

public class ClearVerificationTokenKeysCommand extends AbstractCommandWithDependencies {

  private final Logger logger = LoggerFactory.getLogger(ClearVerificationTokenKeysCommand.class);

  public ClearVerificationTokenKeysCommand() {
    super(new Application<>() {
      @Override
      public void run(WhisperServerConfiguration configuration, Environment environment) {

      }
    }, "clear-verification-keys", "clear cache of trusted JWKS used in verification");
  }

  @Override
  public void configure(Subparser subparser) {
    super.configure(subparser);
    subparser.addArgument("-u", "--uri")
        .dest("uri")
        .type(String.class)
        .required(false)
        .help("The JWKS URI to remove from the cache");
  }

  @Override
  protected void run(Environment environment, Namespace namespace, WhisperServerConfiguration configuration,
      CommandDependencies deps) throws Exception {
    try {
      VerificationTokenKeysManager verificationTokenKeysManager = deps.verificationTokenKeysManager();
      String uri = namespace.getString("uri");
      if (uri.isEmpty()) {
        verificationTokenKeysManager.removeAll().join();
        logger.warn("Removed all verification keys from cache");
      } else {
        Optional<JWKSet> key = verificationTokenKeysManager.findForUri(uri).join();
        if (key.isPresent()) {
          verificationTokenKeysManager.remove(uri).join();
          logger.warn("Removed cached verification keys from URI:" + uri);
        } else {
          logger.warn("Verification keys from the provided URI not found in the cache");
        }
      }
    } catch (Exception ex) {
      logger.warn("Removal Exception", ex);
      throw new RuntimeException(ex);
    }
  }
}
