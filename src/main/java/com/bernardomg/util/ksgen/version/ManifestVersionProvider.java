/**
 * Copyright 2020 the original author or authors
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.bernardomg.util.ksgen.version;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.IVersionProvider;

/**
 * Version provider based on the JAR manifest.
 *
 * @author Bernardo Martínez Garrido
 *
 */
public final class ManifestVersionProvider implements IVersionProvider {

    /**
     * Logger.
     */
    private static final Logger LOGGER  = LoggerFactory.getLogger(ManifestVersionProvider.class);

    /**
     * Project title. Used to identify the correct manifest.
     */
    private static final String project = "Dice Notation Tools CLI";

    public ManifestVersionProvider() {
        super();
    }

    @Override
    public final String[] getVersion() throws Exception {
        final Enumeration<URL> resources = CommandLine.class.getClassLoader()
            .getResources("META-INF/MANIFEST.MF");
        String[]               result;
        Boolean                found;

        result = new String[0];
        found = false;
        while ((!found) && (resources.hasMoreElements())) {
            final URL        url;
            final Manifest   manifest;
            final Attributes attr;
            final String     version;
            final String     finalVersion;

            url = resources.nextElement();

            try {
                manifest = new Manifest(url.openStream());
            } catch (final IOException ex) {
                LOGGER.error("Unable to read from {}", url);
                // TODO: Use detailed error
                throw new RuntimeException();
            }

            if (isValid(manifest)) {
                attr = manifest.getMainAttributes();

                version = "%s version %s";
                finalVersion = String.format(version, get(attr, "Implementation-Title"),
                    get(attr, "Implementation-Version"));
                result = new String[] { finalVersion };
                found = true;
            }
        }

        return result;
    }

    /**
     * Returns the value for the received key.
     *
     * @param attributes
     *            source to get the value
     * @param key
     *            key to search for
     * @return value for the key
     */
    private final Object get(final Attributes attributes, final String key) {
        return attributes.get(new Attributes.Name(key));
    }

    /**
     * Checks if the manifest is the correct one.
     *
     * @param manifest
     *            manifest to check
     * @return {@code true} if it is the expected manifest, {@code false} in other case
     */
    private final Boolean isValid(final Manifest manifest) {
        final Attributes attributes;
        final Object     title;

        attributes = manifest.getMainAttributes();
        title = get(attributes, "Implementation-Title");

        return project.equals(title);
    }

}
