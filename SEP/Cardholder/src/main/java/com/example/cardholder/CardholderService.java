package com.example.cardholder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.apache.tomcat.util.http.fileupload.IOUtils;
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
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.example.cardholder.ConstantKey.*;

@Service
public class CardholderService {
    ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
    @Autowired
    MessageDigest messageDigest;

    @Autowired
    @Qualifier("k1c")
    SecretKeySpec k1c;

    @Autowired
    @Qualifier("k2c")
    SecretKeySpec k2c;

    @Autowired
    @Qualifier("k6c")
    SecretKeySpec k6c;

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
    @Qualifier("issuer")
    KeyPair keyPairIS;

    @Autowired
    @Qualifier("RSA-E")
    Cipher cipherEncryptRSA;

    @Autowired
    @Qualifier("RSA-D")
    Cipher cipherDecryptRSA;


    @Autowired
    private RestTemplate restTemplateWithTrustStore;

    public Map<String, Object> createPurchaseRequest(Map<String, Object> purchaseRequestDto) throws Exception {
        Object orderInformation = purchaseRequestDto.get("order-information");
        Object paymentInstruction = purchaseRequestDto.get("payment-instruction");

        Map<String, Object> pr1_1 = new LinkedHashMap<>();

        String pimd = this.getPIMD(paymentInstruction);

        String oimd = this.getOIMD(orderInformation);

        String dualSignature = this.getDualSignature(oimd, pimd);

        pr1_1.put("oimd", oimd);
        pr1_1.put("pi", paymentInstruction);
        pr1_1.put("dual-signature", dualSignature);
        String pr1Encrypted = this.encryptDES(pr1_1, k2c);
        Map<String, Object> pr1 = new LinkedHashMap<>();
        String pr1_2 = this.encryptRSA(K2_C, keyPairPG);
        pr1.put("pi-ds-oimd-e", pr1Encrypted);
        pr1.put("k2-e", pr1_2);


        Map<String, Object> pr2 = new LinkedHashMap<>();
        Map<String, Object> pr2_1 = new LinkedHashMap<>();
        pr2_1.put("oi", orderInformation);
        pr2_1.put("dual-signature", dualSignature);
        pr2_1.put("pimd", pimd);

        String k1Encrypted = encryptRSA(K1_C, keyPairM);


        pr2.put("oi-ds-pimd", pr2_1);
        pr2.put("k1-e", k1Encrypted);
        Map<String, Object> purchaseRequest = new LinkedHashMap<>();
        purchaseRequest.put("pr1", pr1);
        purchaseRequest.put("pr2", pr2);

        System.out.println(ow.writeValueAsString(purchaseRequest));

        Map<String, Object> response = restTemplateWithTrustStore.postForObject("https://localhost:8081/merchant", purchaseRequest, Map.class);
        Integer code = (Integer) response.get("code");
        if (code != 202) {
            return response;
        }
        try {
            ByteArrayResource certData = restTemplateWithTrustStore.getForObject("https://localhost:8083/issuerBank/getCert", ByteArrayResource.class);
            CertificateFactory certFactory = CertificateFactory.getInstance("X509");
            InputStream certInputStream = new ByteArrayInputStream(certData.getByteArray());
            X509Certificate issuerCertificate = (X509Certificate) certFactory.generateCertificate(certInputStream);
            boolean isVerifiedCertificate = this.verifyCert(new File("keystore.jks"), issuerCertificate);
            if (!isVerifiedCertificate) {
                response.put("certificate-message", "Certificate Issuer not trusted");
                return response;
            }
        } catch (Exception e) {
            response.put("certificate-message", e.getMessage());
            return response;
        }

        String authorizeDataEncrypted = (String) response.get("authorize-data-e");
        String authorizeDataSigned = (String) response.get("authorize-data-s");
        String k5SignedByMerchant = (String) response.get("k5-s");

        String k5m = this.verifySignMessage(k5SignedByMerchant, keyPairM);
        boolean isVerified = this.verifySignMessage(authorizeDataSigned, authorizeDataEncrypted, k5m);
        Map<String, Object> purchaseResponse = new LinkedHashMap<>();
        if (!isVerified) {
            purchaseResponse.put("message", "purchase request not allow");
        } else {
            purchaseResponse.put("purchase-request", purchaseRequest);
            purchaseResponse.put("message", "Purchase request is allow! Please enter your password");
            purchaseResponse.put("token", response.get("token"));
        }
        return purchaseResponse;
    }

    public Map<String, Object> paymentRequest(Map<String, Object> paymentRequest) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String otp = (String) paymentRequest.get("otp");
        String token = (String) paymentRequest.get("token");
        String otpEncrypted = this.encryptRSA(otp, keyPairIS);
        byte[] otpEncryptedHashedBytes = messageDigest.digest(otpEncrypted.getBytes());
        byte[] otpEncryptedHashedEncodedBytes = Base64.getEncoder().encode(otpEncryptedHashedBytes);
        String otpEncryptedHashed = new String(otpEncryptedHashedEncodedBytes);
        Map<String, Object> otpRequest = new LinkedHashMap<>();
        otpRequest.put("otp-e", otpEncrypted);
        otpRequest.put("otp-e-h", otpEncryptedHashed);
        otpRequest.put("token", token);
        System.out.println(ow.writeValueAsString(otpRequest));
        String otpRequestEncrypted = this.encryptDES(otpRequest, k6c);
        String k6EncryptedByPG = this.encryptRSA(K6_C, keyPairPG);
        Map<String, Object> authRequestToPG = new LinkedHashMap<>();
        authRequestToPG.put("otp-request-e", otpRequestEncrypted);
        authRequestToPG.put("k6-e", k6EncryptedByPG);

        Map<String, Object> authData = new LinkedHashMap<>();
        authData.put("token", token);
        String authDataJSON = ow.writeValueAsString(authData);
        byte[] authDataHashedBytes = messageDigest.digest(authDataJSON.getBytes());
        byte[] authDataHashedEncodedBytes = Base64.getEncoder().encode(authDataHashedBytes);
        String authDataHashed = new String(authDataHashedEncodedBytes);
        Map<String, Object> authDataRequest = new LinkedHashMap<>();
        authDataRequest.put("auth-data", authData);
        authDataRequest.put("auth-data-h", authDataHashed);
        String authDataRequestEncrypted = this.encryptDES(authDataRequest, k6c);
        String k6EncryptedByMerchant = this.encryptRSA(K6_C, keyPairM);
        Map<String, Object> authRequestToMerchant = new LinkedHashMap<>();
        authRequestToMerchant.put("auth-data-e", authDataRequestEncrypted);
        authRequestToMerchant.put("k6-e", k6EncryptedByMerchant);

        Map<String, Object> authenticationRequest = new LinkedHashMap<>();
        authenticationRequest.put("auth-data-c-to-pg", authRequestToPG);
        authenticationRequest.put("auth-data-c-to-m", authRequestToMerchant);
        System.out.println(ow.writeValueAsString(authenticationRequest));
        Map<String, Object> paymentResponseFromMerchant = restTemplateWithTrustStore.postForObject("https://localhost:8081/merchant/payment-request", authenticationRequest, Map.class);
        return paymentResponseFromMerchant;
    }

    private boolean verifySignMessage(String signMessage, String cipherText, String keyDecrypted) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
        System.out.println("Verify message start");
        PublicKey publicKey = keyPairM.getPublic();
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

    private String verifySignMessage(String signMessage, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
        PublicKey publicKey = keyPair.getPublic();
        cipherDecryptRSA.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] signMessageBytes = Base64.getDecoder().decode(signMessage.getBytes());
        byte[] signMessageDecryptedBytes = cipherDecryptRSA.doFinal(signMessageBytes);
        return new String(signMessageDecryptedBytes, StandardCharsets.UTF_8);
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

    private String getDualSignature(String oimd, String pimd) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] pomdHash = messageDigest.digest(oimd.concat(pimd).getBytes());
        byte[] pomdHashEncodeBase64 = Base64.getEncoder().encode(pomdHash);
        String pomd = new String(pomdHashEncodeBase64);
        System.out.println(pomd);
        cipherDES.init(Cipher.ENCRYPT_MODE, k1c);
        byte[] byteEncrypted = cipherDES.doFinal(pomd.getBytes());
        byte[] encodeBase64 = Base64.getEncoder().encode(byteEncrypted);
        return new String(encodeBase64);
    }

    private String getOIMD(Object orderInformation) throws JsonProcessingException {
        String oi = ow.writeValueAsString(orderInformation);
        byte[] oiHash = messageDigest.digest(oi.getBytes());
        byte[] oiHashEncode = Base64.getEncoder().encode(oiHash);
        return new String(oiHashEncode);
    }

    private String getPIMD(Object paymentInstruction) throws JsonProcessingException {
        String pi = ow.writeValueAsString(paymentInstruction);
        System.out.println(pi);
        byte[] piHash = messageDigest.digest(pi.getBytes());
        byte[] piHashEncode = Base64.getEncoder().encode(piHash);
        return new String(piHashEncode);
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
