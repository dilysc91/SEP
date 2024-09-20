package com.example.merchant;

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
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.example.merchant.ConstantKey.*;

@Service
public class MerchantService {
    ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
    @Autowired
    MessageDigest messageDigest;

    @Autowired
    @Qualifier("k3m")
    SecretKeySpec k3m;
    @Autowired
    @Qualifier("k5m")
    SecretKeySpec k5m;
    @Autowired
    @Qualifier("k7m")
    SecretKeySpec k7m;

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

    @Autowired
    RestTemplate restTemplateWithTrustStore;

    public Map<String, Object> verifyPurchaseRequest(Map<String, Object> purchaseRequest) {
        try {
            Map<String, Object> pr1 = (Map<String, Object>) purchaseRequest.get("pr1");
            Map<String, Object> pr2 = (Map<String, Object>) purchaseRequest.get("pr2");
            Map<String, Object> oi_ds_pimd = (Map<String, Object>) pr2.get("oi-ds-pimd");
            Map<String, Object> orderInformation = (Map<String, Object>) oi_ds_pimd.get("oi");
            String dualSignature = (String) oi_ds_pimd.get("dual-signature");
            String pimd = (String) oi_ds_pimd.get("pimd");

            String k1Encrypted = (String) pr2.get("k1-e");
            String oimd = this.getOIMD(orderInformation);
            String k1 = this.decryptRSA(k1Encrypted, keyPairM);
            byte[] pomdHash = messageDigest.digest(oimd.concat(pimd).getBytes());
            byte[] pomdHashEncode = Base64.getEncoder().encode(pomdHash);
            String pomdCalcByMerchant = new String(pomdHashEncode);
            String pomdFromDualSignature = this.getPOMDFromDualSignature(dualSignature, k1);
            System.out.println("======Verify Dual Signature...START======");
            System.out.println("K1: " + k1);
            System.out.println(pomdCalcByMerchant + " : pomdCalcByMerchant calc by merchant");
            System.out.println(pomdFromDualSignature + " : pomdFromDualSignature cardholder send");
            if (!pomdCalcByMerchant.equals(pomdFromDualSignature)) {
                System.out.println("Equal() ===> FALSE");
                return Collections.emptyMap();
            }
            System.out.println("Equal() ===> TRUE");
            System.out.println("======Verify Dual Signature...END======");
            String k3MEncryptedByPG = encryptRSA(K3_M, keyPairPG);

            Map<String, Object> authRequest = new HashMap<>();
            authRequest.put("issuer", "shoppe.com.vn");
            authRequest.put("expire", 5000);

            String authRequestHash = this.getHashValueFromObject(authRequest);
            String authRequestEncrypted = this.encryptDES(authRequest, k3m);
            String k1EncryptedByPG = encryptRSA(k1, keyPairPG);
            String signMessage = this.signMessage(authRequestHash, keyPairM);

            Map<String, Object> map = new HashMap<>();
            map.put("k3-e", k3MEncryptedByPG);
            map.put("k1-e", k1EncryptedByPG);
            map.put("auth-request-e", authRequestEncrypted);
            map.put("sign-message", signMessage);


            Map<String, Object> mapWrap = new HashMap<>();
            mapWrap.put("encrypted-pi", pr1);
            mapWrap.put("author-request", map);

            System.out.println(ow.writeValueAsString(mapWrap));

            Map<String, Object> response = restTemplateWithTrustStore.postForObject("https://localhost:8082/payment-gateway/authorRequest", mapWrap, Map.class);
            Integer code = (Integer) response.get("code");
            if (code != 202) {
                return response;
            }
            try {
                ByteArrayResource bar = restTemplateWithTrustStore.getForObject("https://localhost:8083/issuerBank/getCert", ByteArrayResource.class);
                CertificateFactory fac = CertificateFactory.getInstance("X509");
                InputStream is = new ByteArrayInputStream(bar.getByteArray());
                X509Certificate certIssuer = (X509Certificate) fac.generateCertificate(is);
                boolean isVerifiedCert = this.verifyCert(new File("keystore.jks"), certIssuer);
                if (!isVerifiedCert) {
                    response.put("m-message", "Certificate Issuer not trusted");
                    return response;
                }
            } catch (Exception e) {
                response.put("m-message", e.getMessage());
                return response;
            }
            String k4EncryptedByPG = (String) response.get("k4-e");
            String authorizationResponseEncryptedByPG = (String) response.get("authorization-response-e");
            String authorizationResponseSigned = (String) response.get("authorization-response-s");
            String k4pg = this.decryptRSA(k4EncryptedByPG, keyPairM);
            boolean isVerified = this.verifySignMessage(authorizationResponseSigned, authorizationResponseEncryptedByPG, k4pg);
            Map<String, Object> authorizeDataResponse = new LinkedHashMap<>();
            if (!isVerified) {
                authorizeDataResponse.put("message", "message cannot be trusted");
                authorizeDataResponse.put("code", 400);
                return authorizeDataResponse;
            }
            Map<String, Object> authorizeData = new LinkedHashMap<>();
            String authorizeDataEncryptedByMerchant = this.encryptDES(authorizeData, k5m);
            String authorizeDataHashed = this.getHashValueFromObject(authorizeData);
            String authorizeDataSigned = this.signMessage(authorizeDataHashed, keyPairM);
            String k5Signed = this.signMessage(K5_M, keyPairM);
            authorizeDataResponse.put("authorize-data-e", authorizeDataEncryptedByMerchant);
            authorizeDataResponse.put("authorize-data-s", authorizeDataSigned);
            authorizeDataResponse.put("k5-s", k5Signed);
            authorizeDataResponse.put("code", 202);
            authorizeDataResponse.put("token", response.get("token"));
            return authorizeDataResponse;
        } catch (Exception e) {
            e.printStackTrace();
            return Collections.emptyMap();
        }
    }


    public Map<String, Object> doPaymentRequest(Map<String, Object> paymentRequest) {
        Map<String, Object> paymentResponseToCardholder = new LinkedHashMap<>();
        try {
            Map<String, Object> authDataRequestToMerchant = (Map<String, Object>) paymentRequest.get("auth-data-c-to-m");
            Map<String, Object> authDataRequestC2PG = (Map<String, Object>) paymentRequest.get("auth-data-c-to-pg");
            String k6Encrypted = (String) authDataRequestToMerchant.get("k6-e");
            String authDataEncrypted = (String) authDataRequestToMerchant.get("auth-data-e");
            String k6c = this.decryptRSA(k6Encrypted, keyPairM);
            String authDataPlainText = this.decryptDES(authDataEncrypted, k6c);
            JSONObject authData = (JSONObject) new JSONParser().parse(authDataPlainText);

            Map<String, Object> authDataRequest = (Map<String, Object>) authData.get("auth-data");
            String authDataHashedByCardHolder = (String) authData.get("auth-data-h");
            String authDataHashedByMerchant = this.getHashValueFromObject(authDataRequest);
            System.out.println(authDataHashedByCardHolder + ": authDataHashedByCardholder");
            System.out.println(authDataHashedByMerchant + ": authDataHashedByCardholder");
            System.out.println(authDataHashedByMerchant.equals(authDataHashedByCardHolder));

            String k7Encrypted = this.encryptRSA(K7_M, keyPairPG);
            String authDataRequestEncrypted = this.encryptDES(authDataRequest, k7m);
            String authDataRequestHashed = this.getHashValueFromObject(authDataRequest);

            String authDataRequestSigned = this.signMessage(authDataRequestHashed, keyPairM);

            Map<String, Object> authDataRequestM2PG = new LinkedHashMap<>();
            authDataRequestM2PG.put("k7-e", k7Encrypted);
            authDataRequestM2PG.put("auth-data-e", authDataRequestEncrypted);
            authDataRequestM2PG.put("auth-data-s", authDataRequestSigned);

            Map<String, Object> authenticationRequest = new LinkedHashMap<>();
            authenticationRequest.put("auth-data-m-to-pg", authDataRequestM2PG);
            authenticationRequest.put("auth-data-c-to-pg", authDataRequestC2PG);
            System.out.println(ow.writeValueAsString(authenticationRequest));
            Map<String, Object> paymentResponseFromPG = restTemplateWithTrustStore.postForObject("https://localhost:8082/payment-gateway/payment-request", authenticationRequest, Map.class);
            Integer code = (Integer) paymentResponseFromPG.get("code");
            if (code != 202) {
                paymentResponseToCardholder.put("m-message", "Payment unsuccessfully!");
                paymentResponseToCardholder.put("pg-message", paymentResponseFromPG.get("pg-message"));
                paymentResponseToCardholder.put("code", code);
                return paymentResponseToCardholder;
            }
            String paymentResponseEncrypted = (String) paymentResponseFromPG.get("payment-response-e");
            String paymentResponseSigned = (String) paymentResponseFromPG.get("payment-response-s");
            String k8Encrypted = (String) paymentResponseFromPG.get("k8-e");
            String k8 = this.decryptRSA(k8Encrypted, keyPairM);
            boolean isVerified = this.verifySignMessage(paymentResponseSigned, paymentResponseEncrypted, k8);
            if (!isVerified) {
                paymentResponseToCardholder.put("m-message", "Payment unsuccessfully! something went wrong with the payment gateway");
                paymentResponseToCardholder.put("code", code);
                return paymentResponseToCardholder;
            }
            paymentResponseToCardholder.put("m-message", "Payment successfully");

            return paymentResponseToCardholder;
        } catch (Exception e) {
            e.printStackTrace();
            paymentResponseToCardholder.put("m-message", "Payment unsuccessfully");
            paymentResponseToCardholder.put("code", 500);
            return paymentResponseToCardholder;
        }
    }

    private String getPIMD(String pimdEncode) {
        byte[] pimdHashBytes = Base64.getDecoder().decode(pimdEncode.getBytes());
        return new String(pimdHashBytes);
    }

    private String getHashValueFromObject(Map<String, Object> object) throws JsonProcessingException {
        String authRequestJSON = ow.writeValueAsString(object);
        byte[] authRequestHashBytes = messageDigest.digest(authRequestJSON.getBytes());
        byte[] authRequestHashEncode = Base64.getEncoder().encode(authRequestHashBytes);
        return new String(authRequestHashEncode);
    }

    private String getOIMD(Map<String, Object> orderInformation) throws JsonProcessingException {
        String oi = ow.writeValueAsString(orderInformation);
        byte[] oiHash = messageDigest.digest(oi.getBytes());
        byte[] oiHashEncode = Base64.getEncoder().encode(oiHash);
        return new String(oiHashEncode);
    }

    private String getPOMDFromDualSignature(String dualSignature, String key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] decode = Base64.getDecoder().decode(dualSignature.getBytes());
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "DES");
        cipherDES.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] byteEncrypted = cipherDES.doFinal(decode);
        return new String(byteEncrypted);
    }

    private String decryptRSA(String plainText, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey privateKey = keyPair.getPrivate();
        cipherDecryptRSA.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] secretMessageBytes = Base64.getDecoder().decode(plainText.getBytes());
        byte[] decryptedMessageBytes = cipherDecryptRSA.doFinal(secretMessageBytes);
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    private String encryptRSA(String plainText, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PublicKey publicKey = keyPair.getPublic();
        cipherEncryptRSA.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = cipherEncryptRSA.doFinal(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    private String signMessage(String hash, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey privateKey = keyPair.getPrivate();
        cipherEncryptRSA.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] secretMessageBytes = hash.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = cipherEncryptRSA.doFinal(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    private boolean verifySignMessage(String signMessage, String cipherText, String keyDecrypted) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
        System.out.println("Verify message start");
        PublicKey publicKey = keyPairPG.getPublic();
        cipherDecryptRSA.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] signMessageBytes = Base64.getDecoder().decode(signMessage.getBytes());
        byte[] signMessageDecryptedBytes = cipherDecryptRSA.doFinal(signMessageBytes);
        String signMessageHashed = new String(signMessageDecryptedBytes, StandardCharsets.UTF_8);


        String plainText = this.decryptDES(cipherText, keyDecrypted);
        byte[] plainTextHashedBytes = messageDigest.digest(plainText.getBytes());
        byte[] plainTextHashedDecodedBytes = Base64.getEncoder().encode(plainTextHashedBytes);
        String plainTextHashed = new String(plainTextHashedDecodedBytes);
        System.out.println(plainTextHashed + ": plainTextHashed");
        System.out.println(signMessageHashed + ": signMessageHashed");
        System.out.println("Equal -> " + signMessageHashed.equals(plainTextHashed));
        System.out.println("Verify message end");
        return signMessageHashed.equals(plainTextHashed);
    }

    private String encryptDES(Map<String, Object> object, SecretKeySpec keySpec) throws JsonProcessingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String JSONObject = ow.writeValueAsString(object);
        cipherDES.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipherDES.doFinal(JSONObject.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptDES(String authRequestEncrypted, String key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "DES");
        cipherDES.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] byteEncrypted = Base64.getDecoder().decode(authRequestEncrypted);
        byte[] byteDecrypted = cipherDES.doFinal(byteEncrypted);
        return new String(byteDecrypted);
    }

    static boolean verifySigned(File keystore, Certificate agentCertificate) {
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
