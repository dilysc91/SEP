package com.example.paymentgateway;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.example.paymentgateway.ConstantKey.K4_PG;
import static com.example.paymentgateway.ConstantKey.K8_PG;

@Service
public class PaymentGatewayService {
    @Autowired
    private RestTemplate restTemplateWithTrustStore;

    @Autowired
    @Qualifier("k4pg")
    SecretKeySpec k4pg;

    @Autowired
    @Qualifier("k8pg")
    SecretKeySpec k8pg;

    ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
    @Autowired
    MessageDigest messageDigest;

    @Autowired
    @Qualifier("DES")
    Cipher cipherDES;

    @Autowired
    @Qualifier("payment-gateway")
    KeyPair keyPairPG;

    @Autowired
    @Qualifier("merchant")
    KeyPair keyPairM;

    @Autowired
    @Qualifier("RSA-E")
    Cipher cipherEncryptRSA;

    @Autowired
    @Qualifier("RSA-D")
    Cipher cipherDecryptRSA;

    public Map<String, Object> authorRequest(Map<String, Object> authorRequest) {
        try {
            Map<String, Object> map = (Map<String, Object>) authorRequest.get("author-request");
            Map<String, Object> encryptedPi = (Map<String, Object>) authorRequest.get("encrypted-pi");

            String signMessage = (String) map.get("sign-message");
            String authRequestEncrypted = (String) map.get("auth-request-e");
            String k3EncryptedByPG = (String) map.get("k3-e");
            String k1EncryptedByPG = (String) map.get("k1-e");

            String k3m = this.decryptRSA(k3EncryptedByPG, keyPairPG);

            boolean isVerified = this.verifySignMessage(signMessage, authRequestEncrypted, k3m);
            Map<String, Object> responseToMerchant = new LinkedHashMap<>();
            if (!isVerified){
                responseToMerchant.put("code", 400);
                responseToMerchant.put("pg-message", "Auth request cannot trusted");
                return responseToMerchant;
            }
            String k2EncryptedByPG = (String) encryptedPi.get("k2-e");
            String k2c = this.decryptRSA(k2EncryptedByPG, keyPairPG);
            String pi_ds_oimd_encrypted = (String) encryptedPi.get("pi-ds-oimd-e");
            String pi_ds_oimd_plainText = decryptDES(pi_ds_oimd_encrypted, k2c);
            JSONObject obj = (JSONObject) new JSONParser().parse(pi_ds_oimd_plainText);
            String piJSON = obj.get("pi").toString();
            JSONObject pid = (JSONObject) new JSONParser().parse(piJSON);
            Map<String, Object> piLinkedHashMap = new LinkedHashMap<>();
            piLinkedHashMap.put("account-number", pid.get("account-number").toString());
            piLinkedHashMap.put("account-name", pid.get("account-name").toString());
            piLinkedHashMap.put("cvv", pid.get("cvv"));
            piLinkedHashMap.put("expire", pid.get("expire").toString());
            String pi = ow.writeValueAsString(piLinkedHashMap);
            System.out.println(pi);
            String oimd = obj.get("oimd").toString();
            String dualSignature = obj.get("dual-signature").toString();
            String pimd = this.getPIMD(pi);

            String k1c = this.decryptRSA(k1EncryptedByPG, keyPairPG);
            byte[] pomdHash = messageDigest.digest(oimd.concat(pimd).getBytes());
            byte[] pomdHashEncode = Base64.getEncoder().encode(pomdHash);
            String pomdCalcByPaymentGateway = new String(pomdHashEncode);
            String pomdFromDualSignature = this.getPOMDFromDualSignature(dualSignature, k1c);
            System.out.println("======Verify Dual Signature...START======");
            System.out.println("K1: " +k1c);
            System.out.println("K2: " +k2c);
            System.out.println(pomdCalcByPaymentGateway + " : pomdCalcByPaymentGateway calc by Payment Gateway");
            System.out.println(pomdFromDualSignature + " : pomdFromDualSignature merchant send");
            if (!pomdCalcByPaymentGateway.equals(pomdFromDualSignature)) {
                System.out.println("Equal() ===> FALSE");
                return Collections.emptyMap();
            }
            System.out.println("Equal() ===> TRUE");
            System.out.println("======Verify Dual Signature...END======");
            Map<String, Object> authorizeRequest = new HashMap<>();
            authorizeRequest.put("authorizeRequest", "authorizeRequest");
            authorizeRequest.put("pi", piLinkedHashMap);
            Map<String, Object> response = restTemplateWithTrustStore.postForObject("https://localhost:8083/issuerBank/authorizeRequest", authorizeRequest, Map.class);
            Integer code = (Integer) response.get("code");
            if (code != 202) {
                return response;
            }
            Map<String, Object> res = new HashMap<>();
            try {
                ByteArrayResource bar = restTemplateWithTrustStore.getForObject("https://localhost:8083/issuerBank/getCert", ByteArrayResource.class);
                CertificateFactory fac = CertificateFactory.getInstance("X509");
                InputStream is = new ByteArrayInputStream(bar.getByteArray());
                X509Certificate certIssuer = (X509Certificate) fac.generateCertificate(is);
                boolean isVerifiedCert = this.verifyCert(new File("keystore.jks"), certIssuer);
                if (!isVerifiedCert) {
                    res.put("code", 400);
                    res.put("pg-message", "Certificate issuer bank not trusted");
                    return res;
                }
            } catch (Exception e) {
                res.put("code", 500);
                res.put("pg-message", "Certificate issuer bank not trusted");
                return res;
            }


            String authorizationResponseEncryptedByPG = this.encryptDES(response, k4pg);
            String authorizationResponseHashed = this.doHash(response);
            String authorizationResponseSigned = this.signMessage(authorizationResponseHashed, keyPairPG);
            String k4EncryptedByPG = this.encryptRSA(K4_PG, keyPairM);

            responseToMerchant.put("authorization-response-e", authorizationResponseEncryptedByPG);
            responseToMerchant.put("authorization-response-s", authorizationResponseSigned);
            responseToMerchant.put("k4-e", k4EncryptedByPG);
            responseToMerchant.put("code", 202);
            responseToMerchant.put("token", response.get("token"));
            System.out.println(ow.writeValueAsString(responseToMerchant));
            return responseToMerchant;
        } catch (Exception e) {
            e.printStackTrace();
            return Collections.emptyMap();
        }
    }

    public Map<String, Object> doPaymentRequest(Map<String, Object> paymentRequest) {
        Map<String, Object> responseToMerchant = new LinkedHashMap<>();
        try {
            Map<String, Object> authDataFromMerchant = (Map<String, Object>) paymentRequest.get("auth-data-m-to-pg");
            String k7Encrypted = (String) authDataFromMerchant.get("k7-e");
            String authDataEncrypted = (String) authDataFromMerchant.get("auth-data-e");
            String authDataSigned = (String) authDataFromMerchant.get("auth-data-s");
            String k7m = this.decryptRSA(k7Encrypted, keyPairPG);
            boolean isVerified = this.verifySignMessage(authDataSigned, authDataEncrypted, k7m);
            System.out.println(isVerified);

            Map<String, Object> authDataFromCardholder = (Map<String, Object>) paymentRequest.get("auth-data-c-to-pg");
            String otpRequestEncrypted = (String) authDataFromCardholder.get("otp-request-e");
            String k6Encrypted = (String) authDataFromCardholder.get("k6-e");

            String k6c = this.decryptRSA(k6Encrypted, keyPairPG);
            System.out.println("K6 = " + k6c);
            String otpRequestPlainText = this.decryptDES(otpRequestEncrypted, k6c);

            JSONObject otpRequest = (JSONObject) new JSONParser().parse(otpRequestPlainText);
            String otpEncrypted = otpRequest.get("otp-e").toString();
            String otpEncryptedHashed = otpRequest.get("otp-e-h").toString();
            String token = otpRequest.get("token").toString();

            byte[] otpEncryptedHashedBytes = messageDigest.digest(otpEncrypted.getBytes());
            byte[] otpEncryptedHashedEncodedBytes = Base64.getEncoder().encode(otpEncryptedHashedBytes);
            String otpEncryptedHashedByPG = new String(otpEncryptedHashedEncodedBytes);
            System.out.println("otpEncryptedHashed: " + otpEncryptedHashed);
            System.out.println("otpEncryptedHashedByPG: " + otpEncryptedHashedByPG);
            boolean otpIsVerified = otpEncryptedHashed.equals(otpEncryptedHashedByPG);
            System.out.println("otpIsVerified: " + otpIsVerified);

            Map<String, Object> authorizeRequest = new LinkedHashMap<>();
            authorizeRequest.put("auth-data", authDataFromCardholder);
            authorizeRequest.put("otp-e", otpEncrypted);
            authorizeRequest.put("token", token);

            System.out.println(ow.writeValueAsString(authorizeRequest));

            Map<String, Object> paymentResponseFromIB = restTemplateWithTrustStore.postForObject("https://localhost:8083/issuerBank/payment-request", authorizeRequest, Map.class);
            String paymentResponseEncrypted = this.encryptDES(paymentResponseFromIB, k8pg);
            String paymentResponseHashed = this.doHash(paymentResponseFromIB);
            String paymentResponseSigned = this.signMessage(paymentResponseHashed, keyPairPG);
            String k8Encrypted = this.encryptRSA(K8_PG, keyPairM);
            responseToMerchant.put("payment-response-e", paymentResponseEncrypted);
            responseToMerchant.put("payment-response-s", paymentResponseSigned);
            responseToMerchant.put("k8-e", k8Encrypted);
            responseToMerchant.put("code", paymentResponseFromIB.get("code"));
            responseToMerchant.put("pg-message", paymentResponseFromIB.get("message"));
            System.out.println(ow.writeValueAsString(responseToMerchant));
            return responseToMerchant;
        } catch (Exception e) {
            e.printStackTrace();
            responseToMerchant.put("message", e.getMessage());
            responseToMerchant.put("code", 500);
            return responseToMerchant;
        }
    }

    private String doHash(Map<String, Object> object) throws JsonProcessingException {
        String authRequestJSON = ow.writeValueAsString(object);
        byte[] authRequestHashBytes = messageDigest.digest(authRequestJSON.getBytes());
        byte[] authRequestHashEncode = Base64.getEncoder().encode(authRequestHashBytes);
        return new String(authRequestHashEncode);
    }


    private String getPOMDFromDualSignature(String dualSignature, String key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] decode = Base64.getDecoder().decode(dualSignature.getBytes());
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "DES");
        cipherDES.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] byteEncrypted = cipherDES.doFinal(decode);
        return new String(byteEncrypted);
    }

    private String getPIMD(String pi) {
        byte[] piHash = messageDigest.digest(pi.getBytes());
        byte[] piHashEncode = Base64.getEncoder().encode(piHash);
        return new String(piHashEncode);
    }

//    private boolean verifySignMessage1(String signMessage, String authRequestEncrypted, String key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
//        PublicKey publicKey = keyPairM.getPublic();
//        cipherDecryptRSA.init(Cipher.DECRYPT_MODE, publicKey);
//        byte[] secretMessageBytes = Base64.getDecoder().decode(signMessage.getBytes());
//        byte[] decryptedMessageBytes = cipherDecryptRSA.doFinal(secretMessageBytes);
//        String authRequestVerified = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
//
//
//        String authRequestPlainText = this.decryptDES(authRequestEncrypted, key);
//        byte[] authRequestHash = messageDigest.digest(authRequestPlainText.getBytes());
//        byte[] authRequestEncode = Base64.getEncoder().encode(authRequestHash);
//        String authRequestCalcByPG = new String(authRequestEncode);
//        System.out.println("-----verifySignMessage START----");
//        System.out.println(authRequestPlainText);
//        System.out.println(authRequestVerified);
//        System.out.println("-----verifySignMessage END----");
//
//        return authRequestVerified.equals(authRequestPlainText);
//    }

    private String encryptDES(Map<String, Object> object, SecretKeySpec key) throws JsonProcessingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String JSONObject = ow.writeValueAsString(object);
        cipherDES.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipherDES.doFinal(JSONObject.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptDES(String cipherText, String key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "DES");
        cipherDES.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] byteEncrypted = Base64.getDecoder().decode(cipherText);
        byte[] byteDecrypted = cipherDES.doFinal(byteEncrypted);
        return new String(byteDecrypted);
    }

    private String encryptRSA(String plainText, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PublicKey publicKey = keyPair.getPublic();
        cipherEncryptRSA.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = cipherEncryptRSA.doFinal(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    private String decryptRSA(String plainText, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey privateKey = keyPair.getPrivate();
        cipherDecryptRSA.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] secretMessageBytes = Base64.getDecoder().decode(plainText.getBytes());
        byte[] decryptedMessageBytes = cipherDecryptRSA.doFinal(secretMessageBytes);
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    private String signMessage(String hash, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey privateKey = keyPair.getPrivate();
        cipherEncryptRSA.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] secretMessageBytes = hash.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = cipherEncryptRSA.doFinal(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    private boolean verifySignMessage(String signMessage, String cipherText, String key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
        PublicKey publicKey = keyPairM.getPublic();
        cipherDecryptRSA.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] secretMessageBytes = Base64.getDecoder().decode(signMessage.getBytes());
        byte[] decryptedMessageBytes = cipherDecryptRSA.doFinal(secretMessageBytes);
        String signMessageHashed = new String(decryptedMessageBytes, StandardCharsets.UTF_8);


        String plainText = this.decryptDES(cipherText, key);
        byte[] plainTextHashedBytes = messageDigest.digest(plainText.getBytes());
        byte[] plainTextHashedDecodedBytes = Base64.getEncoder().encode(plainTextHashedBytes);
        String plainTextHashed = new String(plainTextHashedDecodedBytes);
        System.out.println(plainTextHashed + ": plainTextHashed");
        System.out.println(signMessageHashed + ": signMessageHashed");
        System.out.println("Equal -> " + signMessageHashed.equals(plainTextHashed));
        System.out.println("Verify message end");
        return signMessageHashed.equals(plainTextHashed);
    }

    private boolean verifyCert(File keystore, java.security.cert.Certificate agentCertificate) {
        try {
            KeyStore store = KeyStore.getInstance("JKS");
            FileInputStream inputStream = new FileInputStream(keystore);
            store.load(inputStream, "rootca@123".toCharArray());
            IOUtils.closeQuietly(inputStream);
            KeyStore.PrivateKeyEntry intermediateEntry = (KeyStore.PrivateKeyEntry) store.getEntry("localhost",
                    new KeyStore.PasswordProtection("exportrca".toCharArray()));
            Certificate intermediateCertificate = intermediateEntry.getCertificate();
            agentCertificate.verify(intermediateCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
