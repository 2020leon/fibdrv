#ifndef BIGNUM_H
#define BIGNUM_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

#define BN_ARRAY_SIZE 7

/* Little-endian */
struct bignum {
    uint32_t num[BN_ARRAY_SIZE];
    int32_t num_and_sign;
};

/* bignum = 0 */
void bignum_init(struct bignum *bignum);
void bignum_from_int(struct bignum *bignum, int64_t i);
void bignum_to_dec(const struct bignum *bignum, char *str, size_t size);

/* c = a + b */
void bignum_add(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c);
/* c = a - b */
void bignum_sub(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c);
/* c = a * b */
void bignum_mul(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c);
/* c = a / b */
void bignum_div(const struct bignum *a,
                const struct bignum *b,
                struct bignum *c);
/* b = -a */
void bignum_neg(const struct bignum *a, struct bignum *b);
/* b = |a| */
void bignum_abs(const struct bignum *a, struct bignum *b);
/* b = a << 1 */
void bignum_shl1(const struct bignum *a, struct bignum *b, uint32_t lsb);
/* b = a >> 1 */
void bignum_shr1(const struct bignum *a, struct bignum *b, uint32_t msb);

#endif
