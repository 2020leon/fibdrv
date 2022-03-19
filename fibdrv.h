#ifndef FIBDRV_H
#define FIBDRV_H

#define FIBDRV_MODE_SIZE 5
enum fibdrv_mode {
    FIBDRV_BIGNUM_FAST,
    FIBDRV_BIGNUM_ORIG,
    FIBDRV_LL_FAST,
    FIBDRV_LL_ORIG,
    FIBDRV_TIME
};

#endif
