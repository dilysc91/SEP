package com.example.issuerbank;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class Card {
    private String accountNumber;
    private String accountName;
    private Integer cvv;
    private String expireDate;
    private String otp;
}
