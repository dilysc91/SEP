package com.example.merchant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/merchant")
public class MerchantController {

    @Autowired
    MerchantService merchantService;

    @PostMapping
    public ResponseEntity<?> abc(@RequestBody Map<String, Object> purchaseRequest) {
        Map<String, Object> response = merchantService.verifyPurchaseRequest(purchaseRequest);
//        Map<String, Object> map = new HashMap<>();
//        if (!response.isEmpty()) {
//            map.put("message", "Successful, verified purchase request! Order information is accepted");
//            map.put("authorize-data", response);
//        } else {
//            map.put("message", "Unsuccessful, not verified purchase request!");
//        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    @PostMapping("payment-request")
    public ResponseEntity<?> paymentRequest(@RequestBody Map<String, Object> paymentRequest) {
        return new ResponseEntity<>(merchantService.doPaymentRequest(paymentRequest),HttpStatus.OK);
    }
}
