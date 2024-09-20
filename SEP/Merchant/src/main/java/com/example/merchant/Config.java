package com.example.merchant;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static com.example.merchant.ConstantKey.*;

@Configuration
public class Config {
    @Bean(name = "k3m")
    public SecretKeySpec k3m() {
        return new SecretKeySpec(K3_M.getBytes(), "DES");
    }

    @Bean(name = "k5m")
    public SecretKeySpec k5m() {
        return new SecretKeySpec(K5_M.getBytes(), "DES");
    }

    @Bean(name = "k7m")
    public SecretKeySpec k7m() {
        return new SecretKeySpec(K7_M.getBytes(), "DES");
    }

    @Bean(name = "DES")
    public Cipher cipherDES() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("DES/ECB/PKCS5PADDING");
    }

    @Bean
    public MessageDigest messageDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-1");
    }

    @Bean(name = "RSA-E")
    public Cipher cipherEncryptRSA() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("RSA");
    }

    @Bean(name = "RSA-D")
    public Cipher cipherDecryptRSA() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("RSA");
    }

    @Bean(name = "merchant")
    public KeyPair keyPairM() {
        KeyPair keyPair;

        File publicKeyFile = new File("../SEP/key-store/merchant-public-key");
        File privateKeyFile = new File("../SEP/key-store/merchant-private-key");

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            keyPair = new KeyPair(publicKey, privateKey);
            return keyPair;
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @Bean(name = "payment-gateway")
    public KeyPair keyPairPG() {
        KeyPair keyPair;

        File publicKeyFile = new File("../SEP/key-store/payment-gateway-public-key");
        File privateKeyFile = new File("../SEP/key-store/payment-gateway-private-key");

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            keyPair = new KeyPair(publicKey, privateKey);
            return keyPair;
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @Value("${trust.store}")
    private Resource trustStore;

    @Value("${trust.store.password}")
    private String trustStorePassword;

    @Bean
    public RestTemplate restTemplate() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException,
            CertificateException, IOException {

        SSLContext sslContext = new SSLContextBuilder()
                .loadTrustMaterial(trustStore.getURL(), trustStorePassword.toCharArray()).build();
        SSLConnectionSocketFactory sslConFactory = new SSLConnectionSocketFactory(sslContext);

        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslConFactory).build();
        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return new RestTemplate(requestFactory);
    }
}
