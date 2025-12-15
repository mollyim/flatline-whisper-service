/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;


import com.fasterxml.jackson.annotation.JsonFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@JsonFilter("Subject")
public class Subject {
  private static final Logger logger = LoggerFactory.getLogger(Subject.class);

  private final String providerId;
  private final String subject;

  public Subject(String providerId, String subject) {
    this.providerId = providerId;
    this.subject = subject;
  }

  public String getProviderId() {
    return providerId;
  }

  public String getSubject() {
    return subject;
  }
}
