# §2+ Payment Logic — Edge Cases
> In addition to basic price/amount manipulation (§2), test these advanced variants:

### 识别信号 (same as §2)
- `amount price total fee payAmount cost discount qty count transport_type freight`

### 决策流程 (advanced)
```
Basic price tampering fails?
├── Data overflow: set amount=2147483649 → wraps to 1
│   → INT_MAX (2147483647) + 1 → 1 due to integer overflow
├── Negative freight: transport_type=-186.00 → total becomes near-zero
│   → Positive item price + negative shipping/coupon = minimal total
├── Rounding exploit: set amount=0.019
│   → Third-party payment rounds to 0.01, server records 0.02
├── Order swap: pay cheap order → replace orderId with expensive order
│   → Server checks payment completed, ignores amount mismatch
├── Order splitting: pair expensive item with bulky item for free shipping
│   → Cancel bulky item after payment → keep free shipping on cheap item
├── Dual-payment race: open payment page on 2 devices simultaneously
│   → Device A pays → Device B pays with same discount → double benefit
├── Coupon enumeration: fuzz couponId/endpoint → find hidden/test coupons
│   → Dev/test coupons with 100% discount, expired but still valid
└── Quantity manipulation: qty=0.1 / qty=-1 / qty=0
```

### Payload (advanced)
```
Overflow values: 2147483648  2147483649  -2147483648  9223372036854775808
Rounding: 0.001  0.019  0.099  0.009
Negative: -1  -0.01  -999
Freight params: transport_type  freight  shipping  delivery_fee
Coupon params: couponId  couponCode  promoCode  voucherId  discountCode
```

---
