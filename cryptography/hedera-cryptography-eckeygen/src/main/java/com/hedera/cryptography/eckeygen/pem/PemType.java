package com.hedera.cryptography.eckeygen.pem;

/**
 * Subset of handled Pem File Types as defined in <a href="https://www.rfc-editor.org/rfc/rfc1422">rfc1422</a>
 */
public enum PemType {

    /**
     * Represents a private key
     */
    PRIVATE_KEY("PRIVATE KEY"),

    /**
     * Represents a public key
     */
    PUBLIC_KEY("PUBLIC KEY");

    private final String pemTypeName;

    private static final String HEADER_FORMAT = "-----BEGIN %s-----\n";
    private static final String FOOTER_FORMAT = "-----END %s-----";

    PemType(final String pemTypeName) {
        this.pemTypeName = pemTypeName;
    }

    /**
     * Returns the footer.
     *
     * @return the formatted footer
     */
    public String getFooter() {
        return String.format(FOOTER_FORMAT, pemTypeName);
    }

    /**
     * Returns the formatted header.
     *
     * @return the header
     */
    public String getHeader() {
        return String.format(HEADER_FORMAT, pemTypeName);
    }
}
