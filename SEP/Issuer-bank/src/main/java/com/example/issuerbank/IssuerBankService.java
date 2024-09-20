package com.example.issuerbank;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class IssuerBankService {

    @Autowired
    @Qualifier("RSA-E")
    Cipher cipherEncryptRSA;

    @Autowired
    @Qualifier("RSA-D")
    Cipher cipherDecryptRSA;

    @Autowired
    @Qualifier("issuer-bank")
    KeyPair keyPairIB;

    @Autowired
    @Qualifier("DES")
    Cipher cipherDES;

    @Autowired
    @Qualifier("k8is")
    SecretKeySpec k8is;

    public Map<String, Object> authorizeRequest(Map<String, Object> o) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> pi = (Map<String, Object>) o.get("pi");
        String accountNumber = (String) pi.get("account-number");
        String accountNumberToQuery = accountNumber.replace(" ", "");
        Card card = this.findAccountByAccountNumber(accountNumberToQuery);

        if (card == null) {
            response.put("message", "ACCOUNT NOT FOUND");
            response.put("code", 400);
            return response;
        }
        String accountName = (String) pi.get("account-name");
        if (!card.getAccountName().equalsIgnoreCase(accountName)) {
            response.put("message", "ACCOUNT NAME NOT VALID");
            response.put("code", 400);
            return response;
        }

        Integer cvv = (Integer) pi.get("cvv");
        if (!card.getCvv().equals(cvv)) {
            response.put("message", "CVV NOT VALID");
            response.put("code", 400);
            return response;
        }

        String expire = (String) pi.get("expire");
        if (!card.getExpireDate().equals(expire)) {
            response.put("message", "EXPIRE NOT VALID");
            response.put("code", 400);
            return response;
        }

        try {
            String token = this.encryptDES(accountNumberToQuery);
            response.put("token", token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        response.put("code", 202);
        response.put("action", "Approval");
        response.put("action-code", 202);
        try {
            System.out.println(new ObjectMapper().writer().withDefaultPrettyPrinter().writeValueAsString(response));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return response;
    }

    public Object doPaymentRequest(Map<String, Object> paymentRequest) {
        Map<String, Object> response = new LinkedHashMap<>();
        try {
            String otpEncrypted = (String) paymentRequest.get("otp-e");
            String token = (String) paymentRequest.get("token");
            String otp = this.decryptRSA(otpEncrypted, keyPairIB);
            String accountNumber;
            try {
                accountNumber = this.decryptDES(token, "K8isbDES");
            } catch (Exception e) {
                response.put("message", "Token is wrong");
                response.put("code", 400);
                return response;
            }
            Card card = this.findAccountByAccountNumber(accountNumber);
            if (card == null) {
                response.put("message", "Token is wrong");
                response.put("code", 400);
                return response;
            }
            if (!card.getOtp().equals(otp)) {
                response.put("message", "OTP is wrong");
                response.put("code", 400);
                return response;
            }
            response.put("message", "Payment successfully");
            response.put("code", 202);
            return response;
        } catch (Exception e) {
            e.printStackTrace();
            response.put("message", e.getMessage());
            return response;
        }
    }


    private Card findAccountByAccountNumber(String accountNumberToQuery) {
        List<Card> cardDB = Arrays.asList(
                new Card("4242424242424242", "DAO THANH DAT", 123, "1026", "12341234"),
                new Card("1111111111111111", "NGUYEN VAN A", 111, "1024", "11111111"),
                new Card("2222222222222222", "NGUYEN THI B", 222, "1023", "22222222"),
                new Card("3333333333333333", "TRAN ANH C", 333, "1022", "33333333")
        );
        return cardDB.stream()
                .filter(card -> card.getAccountNumber().equals(accountNumberToQuery))
                .findFirst()
                .orElse(null);
    }

    public static X509Certificate getCertObject(String filePath)
            throws IOException, CertificateException {
        try (FileInputStream is = new FileInputStream(filePath)) {
            CertificateFactory certificateFactory = CertificateFactory
                    .getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(is);
        }
    }

    private String encryptDES(String plainText) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        cipherDES.init(Cipher.ENCRYPT_MODE, k8is);
        byte[] encrypted = cipherDES.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptDES(String cipherText, String key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "DES");
        cipherDES.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] byteEncrypted = Base64.getDecoder().decode(cipherText);
        byte[] byteDecrypted = cipherDES.doFinal(byteEncrypted);
        return new String(byteDecrypted);
    }

    private String decryptRSA(String plainText, KeyPair keyPair) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey privateKey = keyPair.getPrivate();
        cipherDecryptRSA.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] secretMessageBytes = Base64.getDecoder().decode(plainText.getBytes());
        byte[] decryptedMessageBytes = cipherDecryptRSA.doFinal(secretMessageBytes);
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }
}
