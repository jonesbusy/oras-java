/*-
 * =LICENSE=
 * ORAS Java SDK
 * ===
 * Copyright (C) 2024 - 2026 ORAS
 * ===
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =LICENSEEND=
 */

package land.oras.exception;

import land.oras.auth.HttpClient;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exception for ORAS
 */
@NullMarked
public class OrasException extends RuntimeException {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(OrasException.class);

    /**
     * Possible error response
     */
    private final @Nullable Error error;

    /**
     * Status code
     */
    private final @Nullable Integer statusCode;

    /**
     * Constructor
     * @param message The message
     */
    public OrasException(String message) {
        super(message);
        this.error = null;
        this.statusCode = null;
    }

    /**
     * New exception with a message and a response
     * @param response The response
     */
    public OrasException(HttpClient.ResponseWrapper<String> response) {
        super("Response code: " + response.statusCode());
        Error parsedError = null;
        Integer parsedStatusCode = null;
        String contentType = response.headers().getOrDefault(Const.CONTENT_TYPE_HEADER, "");
        try {
            parsedStatusCode = response.statusCode();
            if (contentType.contains(Const.DEFAULT_JSON_MEDIA_TYPE)) {
                parsedError = JsonUtils.fromJson(response.response(), Error.class);
                LOG.debug("Parsed error response: {}", parsedError);
            } else {
                LOG.debug("Response content type is not JSON, cannot parse error response");
            }
        } catch (Exception e) {
            LOG.debug("Failed to parse error response", e);
        }
        this.error = parsedError;
        this.statusCode = parsedStatusCode;
    }

    /**
     * Constructor
     * @param statusCode The status code
     * @param message The message
     */
    public OrasException(int statusCode, String message) {
        super(message);
        this.error = null;
        this.statusCode = statusCode;
    }

    /**
     * Constructor
     * @param message The message
     * @param cause The cause
     */
    public OrasException(String message, Throwable cause) {
        super(message, cause);
        this.error = null;
        this.statusCode = null;
    }

    /**
     * Get the error
     * @return The error
     */
    public @Nullable Error getError() {
        return error;
    }

    /**
     * Get the status code
     * @return The status code
     */
    public Integer getStatusCode() {
        if (statusCode == null) {
            return -1;
        }
        return statusCode;
    }
}
