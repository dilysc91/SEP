package com.example.merchant;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PaymentInstruction {
    private String accountNumber;
    private String accountName;
    private Integer cvv;
}
