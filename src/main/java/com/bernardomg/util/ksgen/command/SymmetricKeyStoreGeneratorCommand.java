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

package com.bernardomg.util.ksgen.command;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bernardomg.util.ksgen.generator.BouncyCastleKeyStoreFactory;
import com.bernardomg.util.ksgen.generator.KeyStoreFactory;
import com.bernardomg.util.ksgen.version.ManifestVersionProvider;

import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

/**
 * Symmetric key store command. Generates a symmetric key store.
 * 
 * @author Bernardo Martínez Garrido
 *
 */
@Command(name = "symmetric", description = "Creates a symmetric keystore",
        mixinStandardHelpOptions = true,
        versionProvider = ManifestVersionProvider.class)
public final class SymmetricKeyStoreGeneratorCommand implements Runnable {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(SymmetricKeyStoreGeneratorCommand.class);

    /**
     * Keystore alias.
     */
    @Parameters(index = "2", description = "Keystore alias",
            paramLabel = "ALIAS")
    private String              alias;

    /**
     * Keystore password.
     */
    @Parameters(index = "1", description = "Keystore password",
            paramLabel = "PASS")
    private String              password;

    /**
     * Path to create the keystore in.
     */
    @Parameters(index = "0", description = "Path where to create the keystore",
            paramLabel = "PATH")
    private String              path;

    /**
     * Default constructor.
     */
    public SymmetricKeyStoreGeneratorCommand() {
        super();
    }

    @Override
    public final void run() {
        final KeyStore keystore;       // Symmetric key store
        final KeyStoreFactory factory; // KS factory

        factory = new BouncyCastleKeyStoreFactory();

        Security.addProvider(new BouncyCastleProvider());

        LOGGER.debug("Alias {}", alias);
        LOGGER.debug("Saving to {}", path);

        try {
            keystore = factory.getJavaCryptographicExtensionKeyStore(password,
                    alias);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }

        try {
            saveToFile(keystore, path, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Saves the received key store to a file.
     *
     * @param keyStore
     *            key store to save
     * @param path
     *            path where the key store will be saved
     * @param password
     *            password to applyt to the saved key store
     * @throws KeyStoreException
     *             if the keystore has not been initialized
     * @throws NoSuchAlgorithmException
     *             if the appropriate data integrity algorithm could not be
     *             found
     * @throws CertificateException
     *             if any of the certificates included in the key store data
     *             could not be stored
     * @throws IOException
     *             if an I/O error occurs
     */
    private final void saveToFile(final KeyStore keyStore, final String path,
            final char[] password) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        try (final FileOutputStream output = new FileOutputStream(path)) {
            keyStore.store(output, password);
        }
    }

}
