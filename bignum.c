#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#else
#include <stdio.h>
#include <string.h>
#endif

#include "bignum.h"

#ifndef UINT32_MAX
#define UINT32_MAX (4294967295U)
#endif

static void bignum_from_uint_shift_unit(struct bignum *bignum,
                                        uint64_t u,
                                        int unit);
/* c = a / b, d = a % b */
static void bignum_divrem(const struct bignum *a,
                          const struct bignum *b,
                          struct bignum *c,
                          struct bignum *d);
static int bignum_is_zero(const struct bignum *bignum);

void bignum_init(struct bignum *bignum)
{
    memset(bignum, 0, sizeof(*bignum));
}

void bignum_from_int(struct bignum *bignum, int64_t i)
{
    bignum->num[0] = i & UINT32_MAX;
    bignum->num[1] = i >> 32;
    for (int j = 2; j < BN_ARRAY_SIZE; j++)
        bignum->num[j] = -(i < 0);
    bignum->num_and_sign = -(i < 0);
}

void bignum_to_dec(const struct bignum *bignum, char *str, size_t size)
{
    if (!bignum || !str || !size)
        return;
    if (size < 10) {
        *str = '\0';
        return;
    }
    struct bignum base, quo, rem;
    int i;
    bignum_from_int(&base, 1000000000);
    bignum_abs(bignum, &quo);
    *(str + size - 1) = '\0';
    for (i = size - 1 - 9; i >= 0; i -= 9) {
        char buf[10];
        bignum_divrem(&quo, &base, &quo, &rem);
        snprintf(buf, sizeof(buf), "%09u", rem.num[0]);
        memcpy(str + i, buf, 9);
        if (bignum_is_zero(&quo))
            break;
    }
    if (i >= 0) {
        while (*(str + i) == '0' && i < size - 2)
            i++;
        if (bignum->num_and_sign < 0)
            *(str + --i) = '-';
        memmove(str, str + i, size - i);
    } else {
        i += 9;
        if (i > 0)
            memset(str, '.', i);
        else
            memset(str, '.', 9);
    }
}


void bignum_add(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c)
{
    if (!a || !b || !c)
        return;
    uint32_t carry = 0;
    for (int i = 0; i < BN_ARRAY_SIZE; i++) {
        uint64_t tmp = (uint64_t) a->num[i] + b->num[i] + carry;
        carry = (tmp > UINT32_MAX);
        c->num[i] = tmp & UINT32_MAX;
    }
    c->num_and_sign = a->num_and_sign + b->num_and_sign + (int32_t) carry;
}

void bignum_sub(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c)
{
    if (!a || !b || !c)
        return;
    uint32_t carry = 1;
    for (int i = 0; i < BN_ARRAY_SIZE; i++) {
        uint64_t tmp = (uint64_t) a->num[i] + ~b->num[i] + carry;
        carry = (tmp > UINT32_MAX);
        c->num[i] = tmp & UINT32_MAX;
    }
    c->num_and_sign = a->num_and_sign + ~b->num_and_sign + (int32_t) carry;
}

void bignum_mul(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c)
{
    if (!a || !b || !c)
        return;
    uint64_t tmp;
    int sign = ((a->num_and_sign < 0) != (b->num_and_sign < 0));
    struct bignum abs_a, abs_b, big_tmp;
    bignum_abs(a, &abs_a);
    bignum_abs(b, &abs_b);
    bignum_init(c);
    for (int i = 0; i < BN_ARRAY_SIZE; i++) {
        for (int j = 0; i + j <= BN_ARRAY_SIZE && j < BN_ARRAY_SIZE; j++) {
            tmp = (uint64_t) abs_a.num[i] * abs_b.num[j];
            bignum_from_uint_shift_unit(&big_tmp, tmp, i + j);
            bignum_add(c, &big_tmp, c);
        }
    }
    tmp = (uint64_t) abs_a.num[0] * abs_b.num_and_sign;
    bignum_from_uint_shift_unit(&big_tmp, tmp, BN_ARRAY_SIZE);
    bignum_add(c, &big_tmp, c);
    tmp = (uint64_t) abs_a.num_and_sign * abs_b.num[0];
    bignum_from_uint_shift_unit(&big_tmp, tmp, BN_ARRAY_SIZE);
    bignum_add(c, &big_tmp, c);
    if (sign)
        bignum_neg(c, c);
}

// cppcheck-suppress unusedFunction
void bignum_div(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c)
{
    if (!a || !b || !c)
        return;
    int sign = ((a->num_and_sign < 0) != (b->num_and_sign < 0));
    struct bignum abs_a, abs_b;
    bignum_abs(a, &abs_a);
    bignum_abs(b, &abs_b);
    bignum_divrem(&abs_a, &abs_b, c, NULL);
    if (sign)
        bignum_neg(c, c);
}

void bignum_neg(const struct bignum *a, struct bignum *b)
{
    if (!a || !b)
        return;
    uint32_t carry = 1;
    for (int i = 0; i < BN_ARRAY_SIZE; i++) {
        uint64_t tmp = (uint64_t) ~a->num[i] + carry;
        carry = (tmp > UINT32_MAX);
        b->num[i] = tmp & UINT32_MAX;
    }
    b->num_and_sign = ~a->num_and_sign + (int32_t) carry;
}

void bignum_abs(const struct bignum *a, struct bignum *b)
{
    if (!a || !b)
        return;
    const int32_t mask = -(a->num_and_sign < 0);
    b->num[0] = (a->num[0] + mask) ^ mask;
    for (int i = 1; i < BN_ARRAY_SIZE; i++)
        b->num[i] = a->num[i] ^ mask;
    b->num_and_sign = a->num_and_sign ^ mask;
}

void bignum_shl1(const struct bignum *a, struct bignum *b, uint32_t lsb)
{
    if (!a || !b)
        return;
    for (int i = 0; i < BN_ARRAY_SIZE; i++) {
        uint32_t carry = (a->num[i] >> 31) & 1;
        b->num[i] = (a->num[i] << 1) | lsb;
        lsb = carry;
    }
    b->num_and_sign = (a->num_and_sign << 1) | lsb;
}

void bignum_shr1(const struct bignum *a, struct bignum *b, uint32_t msb)
{
    if (!a || !b)
        return;
    uint32_t carry;
    carry = a->num_and_sign & 1;
    b->num_and_sign = ((uint32_t) a->num_and_sign >> 1) | (msb << 31);
    msb = carry;
    for (int i = BN_ARRAY_SIZE - 1; i >= 0; i--) {
        carry = a->num[i] & 1;
        b->num[i] = (a->num[i] >> 1) | (msb << 31);
        msb = carry;
    }
}

static void bignum_from_uint_shift_unit(struct bignum *bignum,
                                        uint64_t u,
                                        int unit)
{
    if (!bignum)
        return;
    bignum_init(bignum);
    if (unit + 1 < BN_ARRAY_SIZE) {
        bignum->num[unit] = u & UINT32_MAX;
        bignum->num[unit + 1] = u >> 32;
    } else if (unit == BN_ARRAY_SIZE - 1) {
        bignum->num[BN_ARRAY_SIZE - 1] = u & UINT32_MAX;
        bignum->num_and_sign = u >> 32;
    } else if (unit == BN_ARRAY_SIZE) {
        bignum->num_and_sign = u & UINT32_MAX;
    }
}

static void bignum_divrem(const struct bignum *a,
                          const struct bignum *b,
                          struct bignum *c,
                          struct bignum *d)
{
    if (!a || !b)
        return;
    struct bignum quo = *a, rem;
    uint32_t carry;
    bignum_init(&rem);

    // 1
    carry = (quo.num_and_sign < 0);
    bignum_shl1(&quo, &quo, 0);
    bignum_shl1(&rem, &rem, carry);

    for (int i = 0; i < sizeof(struct bignum) * 8; i++) {
        // 2
        bignum_sub(&rem, b, &rem);

        if (rem.num_and_sign >= 0) {
            // 3a
            carry = (quo.num_and_sign < 0);
            bignum_shl1(&quo, &quo, 1);
            bignum_shl1(&rem, &rem, carry);
        } else {
            // 3b
            bignum_add(&rem, b, &rem);
            carry = (quo.num_and_sign < 0);
            bignum_shl1(&quo, &quo, 0);
            bignum_shl1(&rem, &rem, carry);
        }
    }

    if (c)
        *c = quo;
    if (d)
        // 4
        bignum_shr1(&rem, d, 0);
}

static int bignum_is_zero(const struct bignum *bignum)
{
    if (!bignum)
        return 0;
    if (bignum->num_and_sign)
        return 0;
    for (int i = 0; i < BN_ARRAY_SIZE; i++) {
        if (bignum->num[i])
            return 0;
    }
    return 1;
}
