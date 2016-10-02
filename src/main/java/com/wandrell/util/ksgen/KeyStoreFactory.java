/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2016 the original author or authors.
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

package com.wandrell.util.ksgen;

import java.security.KeyStore;

/**
 * Factory for generating key stores.
 *
 * @author Bernardo Martínez Garrido
 */
public interface KeyStoreFactory {

    /**
     * Creates a Java Cryptographic Extension Key Store (JCEKS), which will
     * include a secret key.
     *
     * @param password
     *            the password to be used on the key store
     * @param alias
     *            the alias for the secret key
     * @return the JCEKS key store
     * @throws Exception
     *             if any error occurs during the key store creation
     */
    public KeyStore getJavaCryptographicExtensionKeyStore(final String password,
            final String alias) throws Exception;

    /**
     * Creates a Java Key Store (JKS), which will include a certificate.
     *
     * @param password
     *            password for the certificate
     * @param alias
     *            alias for the certificate
     * @param issuer
     *            issuer for the certificate
     * @return the JKS key store
     * @throws Exception
     *             if any error occurs during the key store creation
     */
    public KeyStore getJavaKeyStore(final String password, final String alias,
            final String issuer) throws Exception;

}
