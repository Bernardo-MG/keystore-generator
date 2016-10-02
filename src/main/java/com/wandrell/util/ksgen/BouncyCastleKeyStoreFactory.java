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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bouncy Castle based factory for generating key stores.
 *
 * @author Bernardo Martínez Garrido
 */
public final class BouncyCastleKeyStoreFactory extends AbstractKeyStoreFactory {

    /**
     * The logger used for logging the key store creation.
     */
    private static final Logger LOGGER             = LoggerFactory
            .getLogger(BouncyCastleKeyStoreFactory.class);

    /**
     * Random values generator.
     * <p>
     * To be used whenever a new random value is required.
     */
    private final Random        random             = new Random();

    /**
     * The algorithm to be used for the secret key.
     */
    private final String        secretKeyAlgorithm = "DES";

    /**
     * The algorith to use for the signature.
     */
    private final String        signatureAlgorithm = "SHA256WithRSAEncryption";

    /**
     * Default constructor.
     */
    public BouncyCastleKeyStoreFactory() {
        super();
    }

    /**
     * Returns a {@code SubjectKeyIdentifier} for the received {@code Key}.
     *
     * @param key
     *            the key for generating the identifier
     * @return a {@code SubjectKeyIdentifier} for the received {@code Key}
     * @throws IOException
     *             if any problem occurs while reading the key
     */
    private final SubjectKeyIdentifier createSubjectKeyIdentifier(final Key key)
            throws IOException {
        final ASN1Sequence seq;        // Sequence for the key info
        ASN1InputStream stream = null; // Stream for reading the key

        try {
            stream = new ASN1InputStream(
                    new ByteArrayInputStream(key.getEncoded()));
            seq = (ASN1Sequence) stream.readObject();
        } finally {
            IOUtils.closeQuietly(stream);
        }

        return new BcX509ExtensionUtils()
                .createSubjectKeyIdentifier(new SubjectPublicKeyInfo(seq));
    }

    /**
     * Returns a {@code Certificate} with the received data.
     *
     * @param keypair
     *            key pair for the certificate
     * @param issuer
     *            issuer for the certificate
     * @return a {@code Certificate} with the received data
     * @throws IOException
     *             if there is an I/O or format problem with the certificate
     *             data
     * @throws OperatorCreationException
     *             if there was a problem creation a bouncy castle operator
     * @throws CertificateException
     *             if any of the certificates in the keystore could not be
     *             loaded
     * @throws InvalidKeyException
     *             if there was a problem with the key
     * @throws NoSuchAlgorithmException
     *             if an algorithm required to create the key store could not be
     *             found
     * @throws NoSuchProviderException
     *             if a required provider is missing
     * @throws SignatureException
     *             if any problem occurs while signing the certificate
     */
    private final Certificate getCertificate(final KeyPair keypair,
            final String issuer) throws IOException, OperatorCreationException,
            CertificateException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException {
        final X509v3CertificateBuilder builder; // Certificate builder
        final X509Certificate certificate;      // Certificate

        // Generates the certificate builder
        builder = getCertificateBuilder(keypair.getPublic(), issuer);

        // Generates the signed certificate
        certificate = getSignedCertificate(builder, keypair.getPrivate());

        // Verifies the certificate
        certificate.checkValidity(getCurrentDate());
        certificate.verify(keypair.getPublic());

        LOGGER.debug("Created certificate of type {} with encoded value {}",
                certificate.getType(), Arrays.asList(certificate.getEncoded()));
        LOGGER.debug("Created certificate with public key:{}",
                certificate.getPublicKey());

        return certificate;
    }

    /**
     * Returns a certificate builder.
     *
     * @param publicKey
     *            public key for the certificate builder
     * @param issuer
     *            issuer for the certificate builder
     * @return a certificate builder
     * @throws IOException
     *             if any format error occurrs while creating the certificate
     */
    private final X509v3CertificateBuilder getCertificateBuilder(
            final PublicKey publicKey, final String issuer) throws IOException {
        final X500Name issuerName;              // Issuer name
        final X500Name subjectName;             // Subject name
        final BigInteger serial;                // Serial number
        final X509v3CertificateBuilder builder; // Certificate builder
        final Date start;                       // Certificate start date
        final Date end;                         // Certificate end date
        final KeyUsage usage;                   // Key usage
        final ASN1EncodableVector purposes;     // Certificate purposes

        issuerName = new X500Name(issuer);
        subjectName = issuerName;
        serial = BigInteger.valueOf(getRandom().nextInt());

        // Dates for the certificate
        start = getOneYearBackDate();
        end = getOneHundredYearsFutureDate();

        builder = new JcaX509v3CertificateBuilder(issuerName, serial, start,
                end, subjectName, publicKey);

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                createSubjectKeyIdentifier(publicKey));
        builder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(true));

        usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature
                | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment
                | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, false, usage);

        purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false,
                new DERSequence(purposes));

        return builder;

    }

    /**
     * Returns the current date.
     * 
     * @return the current date
     */
    private final Date getCurrentDate() {
        return new Date();
    }

    /**
     * Creates a key pair.
     *
     * @return the key pair
     * @throws NoSuchAlgorithmException
     *             if the required algorithm for the key pair does not exist
     */
    private final KeyPair getKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator; // Key pair generator
        final KeyPair keypair;                   // Key pair

        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());

        keypair = keyPairGenerator.generateKeyPair();

        LOGGER.debug(
                "Created key pair with private key {} {} and public key {} {}",
                keypair.getPrivate().getAlgorithm(),
                Arrays.asList(keypair.getPrivate().getEncoded()),
                keypair.getPublic().getAlgorithm(),
                Arrays.asList(keypair.getPublic().getEncoded()));

        return keypair;
    }

    /**
     * Returns a date for this day one hundred years in the future.
     * 
     * @return a date one hundred years in the future
     */
    private final Date getOneHundredYearsFutureDate() {
        final Long msDay;       // Milliseconds in a day
        final Integer yearDays; // Days in a year
        final Integer years;    // Number of years

        msDay = 86400000L;
        yearDays = 365;
        years = 100;

        return new Date(System.currentTimeMillis() - msDay * yearDays * years);
    }

    /**
     * Returns a date for this day the previous year.
     * 
     * @return a date one year back
     */
    private final Date getOneYearBackDate() {
        final Long msDay;       // Milliseconds in a day
        final Integer yearDays; // Days in a year

        msDay = 86400000L;
        yearDays = 365;

        return new Date(System.currentTimeMillis() - msDay * yearDays);
    }

    /**
     * Returns the password as a byte array.
     * 
     * @param password
     *            the password to transform into a byte array
     * @return the password as a byte array
     */
    private final byte[] getPasswordArray(final String password) {
        // TODO: This always returns the same value
        return new byte[] { 1, 2, 3, 4, 5 };
    }

    /**
     * Returns the random values generator.
     * 
     * @return the random values generator
     */
    private final Random getRandom() {
        return random;
    }

    /**
     * Returns the algorithm to be used for the secret key.
     * 
     * @return the algorithm to be used for the secret key
     */
    private final String getSecretKeyAlgorithm() {
        return secretKeyAlgorithm;
    }

    /**
     * Returns the algorithm to use for the signature.
     * 
     * @return
     */
    private final String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Returns a signed certificate.
     *
     * @param builder
     *            builder to create the certificate
     * @param key
     *            private key for the certificate
     * @return a signed certificate
     * @throws OperatorCreationException
     *             if there was a problem creation a bouncy castle operator
     * @throws CertificateException
     *             if any of the certificates in the keystore could not be
     *             loaded
     */
    private final X509Certificate getSignedCertificate(
            final X509v3CertificateBuilder builder, final PrivateKey key)
            throws OperatorCreationException, CertificateException {
        final ContentSigner signer;   // Content signer
        final String provider;        // Provider
        final X509Certificate signed; // Signed certificate

        provider = BouncyCastleProvider.PROVIDER_NAME;
        signer = new JcaContentSignerBuilder(getSignatureAlgorithm())
                .setProvider(provider).build(key);

        signed = new JcaX509CertificateConverter().setProvider(provider)
                .getCertificate(builder.build(signer));

        LOGGER.debug(
                "Signed certificate with {} private key {}, using algorithm {}",
                key.getAlgorithm(), Arrays.asList(key.getEncoded()),
                key.getFormat());

        return signed;
    }

    @Override
    protected final void addCertificate(final KeyStore kstore,
            final String password, final String alias, final String issuer)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, OperatorCreationException,
            CertificateException, IOException, KeyStoreException,
            SignatureException {
        final KeyPair keypair;          // Key pair for the certificate
        final Certificate certificate;  // Generated certificate
        final Certificate[] chain;      // Certificate chain

        // Creates a key pair
        keypair = getKeyPair();

        // Creates a certificate
        certificate = getCertificate(keypair, issuer);

        // Creates the certificates chain
        chain = new Certificate[] { certificate };

        // Sets the key data into the key store
        kstore.setKeyEntry(alias, keypair.getPrivate(), password.toCharArray(),
                chain);

        LOGGER.debug(
                "Added certificate with alias {} and password {} for issuer {}",
                alias, password, issuer);
    }

    @Override
    protected final void addSecretKey(final KeyStore kstore, final String alias,
            final String password) throws KeyStoreException {
        final SecretKeyEntry secretKeyEntry;  // Secret key entry
        final PasswordProtection keyPassword; // Secret key password protection
        final SecretKey secretKey;            // Secret key password
        final byte[] key;                     // Secret key as array

        key = getPasswordArray(password);
        secretKey = new SecretKeySpec(key, getSecretKeyAlgorithm());

        LOGGER.debug("Created secret key {} with format {}",
                Arrays.asList(secretKey.getEncoded()), secretKey.getFormat());

        secretKeyEntry = new SecretKeyEntry(secretKey);
        keyPassword = new PasswordProtection(password.toCharArray());
        kstore.setEntry(alias, secretKeyEntry, keyPassword);

        LOGGER.debug("Added secret key with alias {} and password {}", alias,
                password);
    }

    @Override
    protected final KeyStore getKeystore(final String password)
            throws NoSuchAlgorithmException, CertificateException, IOException,
            KeyStoreException {
        return getKeystore(password, KeyStore.getDefaultType());
    }

    @Override
    protected final KeyStore getKeystore(final String password,
            final String type) throws NoSuchAlgorithmException,
            CertificateException, IOException, KeyStoreException {
        final KeyStore kstore; // The returned key store
        final char[] pass;     // The key store password

        kstore = KeyStore.getInstance(type);

        pass = password.toCharArray();
        kstore.load(null, pass);

        LOGGER.debug("Created {} key store with password {}", type, password);

        return kstore;
    }

}
