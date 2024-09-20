package com.example.cardholder;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@RequestMapping("/cardholder")
public class CardholderController {
    @Autowired
    CardholderService cardholderService;


    @PostMapping("create-purchase-request")
    public ResponseEntity<?> createPurchaseRequest(@RequestBody Map<String, Object> purchaseRequestDto) throws Exception {
        Map<String, Object> purchaseRequest = cardholderService.createPurchaseRequest(purchaseRequestDto);
        return new ResponseEntity<>(purchaseRequest, HttpStatus.OK);
    }

    @PostMapping("payment-request")
    public ResponseEntity<?> paymentRequest(@RequestBody Map<String, Object> purchaseRequestDto) throws Exception {
        Map<String, Object> purchaseRequest = cardholderService.paymentRequest(purchaseRequestDto);
        return new ResponseEntity<>(purchaseRequest, HttpStatus.OK);
    }
}
