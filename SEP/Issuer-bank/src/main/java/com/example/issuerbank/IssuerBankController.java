package com.example.issuerbank;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

@RestController
@RequestMapping("issuerBank")
public class IssuerBankController {

    @Autowired
    private ServletContext servletContext;
    @Autowired
    IssuerBankService issuerBankService;

    @PostMapping("/authorizeRequest")
    public ResponseEntity<?> authorizeRequest(@RequestBody Map<String, Object> o){
        return new ResponseEntity<>(issuerBankService.authorizeRequest(o), HttpStatus.OK);
    }

    @PostMapping("/payment-request")
    public ResponseEntity<?> paymentRequest(@RequestBody Map<String,Object> paymentRequest){
        return new ResponseEntity<>(issuerBankService.doPaymentRequest(paymentRequest), HttpStatus.OK);
    }

    @RequestMapping("/getCert")
    public ResponseEntity<?> getCert() throws IOException {
        Path path = Paths.get("Issuer-bank/src/main/resources/ib.crt");
//        Path path = Paths.get("Issuer-bank/src/main/resources/baeldung.p12");
        byte[] data = Files.readAllBytes(path);
        ByteArrayResource resource = new ByteArrayResource(data);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(data.length)
                .body(resource);
    }
}
