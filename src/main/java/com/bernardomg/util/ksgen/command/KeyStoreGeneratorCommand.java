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

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bernardomg.util.ksgen.generator.BouncyCastleKeyStoreFactory;
import com.bernardomg.util.ksgen.generator.KeyStoreFactory;
import com.bernardomg.util.ksgen.version.ManifestVersionProvider;

import picocli.CommandLine.Command;

/**
 * Roll command. Receives an expression, rolls it and prints the result on
 * screen.
 * 
 * @author Bernardo Martínez Garrido
 *
 */
@Command(name = "roll", description = "Rolls an expression",
        mixinStandardHelpOptions = true,
        versionProvider = ManifestVersionProvider.class)
public final class KeyStoreGeneratorCommand implements Runnable {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(KeyStoreGeneratorCommand.class);

    public KeyStoreGeneratorCommand() {
        super();
    }

    @Override
    public final void run() {
        final KeyStore jksMain;        // Main key store
        final KeyStore jceksSym;       // Symmetric key store
        final String jksMainPath;      // Path for the main key store
        final String jceksSymPath;     // Path for the symmetric key store
        final String password;         // Password to apply to the key stores
        final String alias;            // Alias for the certificate
        final String issuer;           // Issuer for the certificate
        final KeyStoreFactory factory; // KS factory

        factory = new BouncyCastleKeyStoreFactory();

        jksMainPath = "src/main/resources/keystore.jks";
        jceksSymPath = "src/main/resources/symmetric.jceks";

        password = "123456";
        alias = "swss-cert";
        issuer = "CN=www.bernardomg.com, O=bernardomg, OU=None, L=London, ST=England, C=UK";

        Security.addProvider(new BouncyCastleProvider());

        // Main key store

        LOGGER.trace("Creating main key store");

        try {
            jksMain = factory.getJavaKeyStore(password, alias, issuer);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }

        // Saves the main keystore
        try {
            saveToFile(jksMain, jksMainPath, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }

        LOGGER.trace("Created main key store");

        // Symmetric key store

        LOGGER.trace("Creating symmetric key store");

        try {
            jceksSym = factory.getJavaCryptographicExtensionKeyStore(password,
                    alias);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }

        // Saves the symmetric key store
        try {
            saveToFile(jceksSym, jceksSymPath, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }

        LOGGER.trace("Created symmetric key store");

        LOGGER.trace("Finished creating key stores");
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
    private static final void saveToFile(final KeyStore keyStore,
            final String path, final char[] password) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        FileOutputStream output = null; // Output stream for the key store

        try {
            output = new FileOutputStream(path);
            keyStore.store(output, password);
        } finally {
            IOUtils.closeQuietly(output);
        }
    }

}
