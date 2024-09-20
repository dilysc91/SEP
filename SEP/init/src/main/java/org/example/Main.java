package org.example;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Main {
    public static final String K1_C = "Key1DESC";
    public static final String K2_C = "Key2DESC";
    public static final String K3_M = "Key3DESM";
    public static final String K4_PG = "Key4DESP";
    public static final String K6_C = "Key6DESc";
    public static final String KUM = "Public key RSA merchant";
    public static final String KRM = "Private key RSA merchant";
    public static final String KUPG = "Public key RSA payment gateway";
    public static final String KRPG = "Private key RSA payment gateway";

    public static void main(String[] args) {
        writeFileKeyDES(K1_C, "key-1-des-cardholder");
        writeFileKeyDES(K2_C, "key-2-des-cardholder");
        writeFileKeyDES(K3_M, "key-3-des-merchant");
        writeFileKeyDES(K4_PG, "key-4-des-payment-gateway");

        writeFileKeyPairRSAMerchant();
        writeFileKeyPairRSAPaymentGateway();
        writeFileKeyPairRSAIssuer();


    }

    private static void writeFileKeyPairRSAIssuer() {
        KeyPair keyPair;
        File directory = new File("../SEP/key-store");

        if (!directory.exists()) {
            directory.mkdir();
        }
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
            try (FileOutputStream fos = new FileOutputStream("../SEP/key-store/issuer-public-key")) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
                fos.write(keySpec.getEncoded());
            }

            try (FileOutputStream fos = new FileOutputStream("../SEP/key-store/issuer-private-key")) {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
                fos.write(keySpec.getEncoded());
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeFileKeyPairRSAPaymentGateway() {
        KeyPair keyPair;
        File directory = new File("../SEP/key-store");

        if (!directory.exists()) {
            directory.mkdir();
        }
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
            try (FileOutputStream fos = new FileOutputStream("../SEP/key-store/payment-gateway-public-key")) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
                fos.write(keySpec.getEncoded());
            }

            try (FileOutputStream fos = new FileOutputStream("../SEP/key-store/payment-gateway-private-key")) {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
                fos.write(keySpec.getEncoded());
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeFileKeyPairRSAMerchant() {
        KeyPair keyPair;
        File directory = new File("../SEP/key-store");

        if (!directory.exists()) {
            directory.mkdir();
        }
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
            try (FileOutputStream fos = new FileOutputStream("../SEP/key-store/merchant-public-key")) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
                fos.write(keySpec.getEncoded());
            }

            try (FileOutputStream fos = new FileOutputStream("../SEP/key-store/merchant-private-key")) {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
                fos.write(keySpec.getEncoded());
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }


    private static void writeFileKeyDES(String key, String fileName) {
        File directory = new File("../SEP/key-store");

        if (!directory.exists()) {
            directory.mkdir();
        }
        try (FileOutputStream fos = new FileOutputStream("../SEP/key-store/" + fileName)) {
            fos.write(key.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}