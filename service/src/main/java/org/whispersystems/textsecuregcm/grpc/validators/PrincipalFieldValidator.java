/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.grpc.validators;

import static org.whispersystems.textsecuregcm.grpc.validators.ValidatorUtils.invalidArgument;

import com.google.protobuf.Descriptors;
import io.grpc.StatusException;
import java.util.Set;
import org.whispersystems.textsecuregcm.util.InvalidPrincipalException;
import org.whispersystems.textsecuregcm.util.NonNormalizedPrincipalException;
import org.whispersystems.textsecuregcm.util.Util;

public class PrincipalFieldValidator extends BaseFieldValidator<Boolean> {

  public PrincipalFieldValidator() {
    super("principal", Set.of(Descriptors.FieldDescriptor.Type.STRING), MissingOptionalAction.SUCCEED, false);
  }

  @Override
  protected Boolean resolveExtensionValue(final Object extensionValue) throws StatusException {
    return requireFlagExtension(extensionValue);
  }

  @Override
  protected void validateStringValue(
      final Boolean extensionValue,
      final String fieldValue) throws StatusException {
    try {
      Util.requireNormalizedPrincipal(fieldValue);
    } catch (final InvalidPrincipalException | NonNormalizedPrincipalException e) {
      throw invalidArgument("value is not in principal format");
    }
  }
}
