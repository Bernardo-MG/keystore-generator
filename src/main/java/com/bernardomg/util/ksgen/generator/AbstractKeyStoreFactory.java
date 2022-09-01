/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2016-2020 the original author or authors.
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.bernardomg.util.ksgen.generator;

import java.security.KeyStore;
import java.util.Objects;

/**
 * Base factory for generating key stores.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 */
public abstract class AbstractKeyStoreFactory implements KeyStoreFactory {

    /**
     * Default constructor.
     */
    public AbstractKeyStoreFactory() {
        super();
    }

    @Override
    public final KeyStore getJavaCryptographicExtensionKeyStore(final String password, final String alias)
            throws Exception {
        final KeyStore kstore; // Generated key store

        Objects.requireNonNullElse(password, "Received a null pointer as password");
        Objects.requireNonNullElse(alias, "Received a null pointer as alias");

        kstore = getKeystore(password, "JCEKS");
        addSecretKey(kstore, alias, password);

        return kstore;
    }

    @Override
    public final KeyStore getJavaKeyStore(final String password, final String alias, final String issuer)
            throws Exception {
        final KeyStore kstore; // Generated key store

        Objects.requireNonNullElse(password, "Received a null pointer as password");
        Objects.requireNonNullElse(alias, "Received a null pointer as alias");
        Objects.requireNonNullElse(issuer, "Received a null pointer as issuer");

        kstore = getKeystore(password);
        addCertificate(kstore, password, alias, issuer);

        return kstore;
    }

    /**
     * Adds a certificate to a key store.
     *
     * @param kstore
     *            key store where the certificate will be added
     * @param password
     *            password for the certificate
     * @param alias
     *            alias for the certificate
     * @param issuer
     *            certificate issuer
     * @throws Exception
     *             if any problem occurs while creating the key store
     */
    protected abstract void addCertificate(final KeyStore kstore, final String password, final String alias,
            final String issuer) throws Exception;

    /**
     * Adds a secret key to the received key store.
     *
     * @param kstore
     *            key store where the secret key will be added
     * @param alias
     *            alias for the secret key
     * @param password
     *            password for the secret key
     * @throws Exception
     *             if any problem occurs while creating the key store
     */
    protected abstract void addSecretKey(final KeyStore kstore, final String alias, final String password)
            throws Exception;

    /**
     * Generates a default JKS key store.
     *
     * @param password
     *            the password for the key store
     * @return the JKS key store
     * @throws Exception
     *             if any problem occurs while creating the key store
     */
    protected abstract KeyStore getKeystore(final String password) throws Exception;

    /**
     * Generates a key store of the specified type.
     *
     * @param password
     *            the password for the key store
     * @param type
     *            the type of the key store
     * @return a key store of the specified type
     * @throws Exception
     *             if any problem occurs while creating the key store
     */
    protected abstract KeyStore getKeystore(final String password, final String type) throws Exception;

}
