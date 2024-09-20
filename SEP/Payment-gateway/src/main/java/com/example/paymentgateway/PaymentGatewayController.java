package com.example.paymentgateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

@RestController
@RequestMapping("/payment-gateway")
public class PaymentGatewayController {

    @Autowired
    PaymentGatewayService paymentGatewayService;

    @PostMapping("/authorRequest")
    public ResponseEntity<?> authorRequest(@RequestBody Map<String, Object> authorRequest) {
        Map<String, Object> response = paymentGatewayService.authorRequest(authorRequest);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/payment-request")
    public ResponseEntity<?> paymentRequest(@RequestBody Map<String, Object> paymentRequest) {
        Map<String, Object> response = paymentGatewayService.doPaymentRequest(paymentRequest);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }


    @RequestMapping("/getCert")
    public ResponseEntity<?> getCert() throws IOException {
        Path path = Paths.get("Merchant/src/main/resources/ib.crt");
        byte[] data = Files.readAllBytes(path);
        ByteArrayResource resource = new ByteArrayResource(data);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(data.length)
                .body(resource);
    }
}
