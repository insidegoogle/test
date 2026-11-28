#ifndef _SECP256K1_CL
#define _SECP256K1_CL

typedef ulong uint64_t;

typedef struct {
    uint v[8];
} uint256_t;


/*===============================================================
 * Constants
 *===============================================================*/

__constant uint _P[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2F
};

__constant uint _P_MINUS1[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2F
};

__constant uint _GX[8] = {
    0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07,
    0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798
};

__constant uint _GY[8] = {
    0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8,
    0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8
};

__constant uint _N[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
    0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141
};

__constant uint _INFINITY[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};


/*===============================================================
 * Low-level helpers
 *===============================================================*/

inline uint addc(uint a, uint b, uint *carry)
{
    uint sum = a + *carry;
    uint c1 = (sum < a);
    sum += b;
    uint c2 = (sum < b);
    *carry = c1 | c2;
    return sum;
}

inline uint subc(uint a, uint b, uint *borrow)
{
    uint diff = a - *borrow;
    *borrow = (diff > a);
    uint diff2 = diff - b;
    *borrow |= (diff2 > diff);
    return diff2;
}

#ifdef DEVICE_VENDOR_INTEL
inline uint mul_hi977(uint x)
{
    uint high = x >> 16;
    uint low  = x & 0xffff;
    return (((low * 977) >> 16) + (high * 977)) >> 16;
}

inline void madd977(uint *high, uint *low, uint a, uint c)
{
    *low = a * 977;
    uint tmp = *low + c;
    uint carry = (tmp < *low);
    *low = tmp;
    *high = mul_hi977(a) + carry;
}
#else
inline void madd977(uint *high, uint *low, uint a, uint c)
{
    *low = a * 977;
    uint tmp = *low + c;
    uint carry = (tmp < *low);
    *low = tmp;
    *high = mad_hi(a, (uint)977, carry);
}
#endif

inline void madd(uint *high, uint *low, uint a, uint b, uint c)
{
    *low = a * b;
    uint tmp = *low + c;
    uint carry = (tmp < *low);
    *low = tmp;
    *high = mad_hi(a, b, carry);
}

inline void mull(uint *high, uint *low, uint a, uint b)
{
    *low  = a * b;
    *high = mul_hi(a, b);
}


/*===============================================================
 * 256-bit arithmetic
 *===============================================================*/

uint256_t sub256k(uint256_t a, uint256_t b, uint *borrow_ptr)
{
    uint borrow = 0;
    uint256_t c;
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        c.v[i] = subc(a.v[i], b.v[i], &borrow);
    }
    *borrow_ptr = borrow;
    return c;
}

uint256_t add256k(uint256_t a, uint256_t b, uint *carry_ptr)
{
    uint carry = 0;
    uint256_t c;
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        c.v[i] = addc(a.v[i], b.v[i], &carry);
    }
    *carry_ptr = carry;
    return c;
}

uint add256(const uint a[8], const uint b[8], uint c[8])
{
    uint carry = 0;
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        c[i] = addc(a[i], b[i], &carry);
    }
    return carry;
}

uint addP(const uint a[8], uint c[8])
{
    uint carry = 0;
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        c[i] = addc(a[i], _P[i], &carry);
    }
    return carry;
}

uint subP(const uint a[8], uint c[8])
{
    uint borrow = 0;
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        c[i] = subc(a[i], _P[i], &borrow);
    }
    return borrow;
}

bool greaterThanEqualToP(const uint a[8])
{
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (a[i] > _P_MINUS1[i]) return true;
        if (a[i] < _P_MINUS1[i]) return false;
    }
    return true;
}

bool isInfinity(const uint x[8])
{
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (x[i] != 0xffffffff) return false;
    }
    return true;
}

bool isInfinity256k(const uint256_t x)
{
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (x.v[i] != 0xffffffff) return false;
    }
    return true;
}

bool equal(const uint a[8], const uint b[8])
{
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool equal256k(uint256_t a, uint256_t b)
{
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (a.v[i] != b.v[i]) return false;
    }
    return true;
}


/*===============================================================
 * Modular addition / subtraction
 *===============================================================*/

uint256_t subModP256k(uint256_t a, uint256_t b)
{
    uint borrow = 0;
    uint256_t c = sub256k(a, b, &borrow);
    if (borrow) {
        addP(c.v, c.v);
    }
    return c;
}

uint256_t addModP256k(uint256_t a, uint256_t b)
{
    uint carry = 0;
    uint256_t c = add256k(a, b, &carry);

    bool ge = false;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (c.v[i] > _P[i]) { ge = true; break; }
        if (c.v[i] < _P[i]) break;
    }

    if (carry || ge) {
        subP(c.v, c.v);
    }
    return c;
}


/*===============================================================
 * 256×256 multiplication
 *===============================================================*/

void multiply256(const uint x[8], const uint y[8], uint out_high[8], uint out_low[8])
{
    uint z[16];

    // First row
    uint64_t product = (uint64_t)x[7] * y[7];
    z[15] = (uint)product;
    uint high = (uint)(product >> 32);

    #pragma unroll
    for (int j = 6; j >= 0; j--) {
        product = (uint64_t)x[7] * y[j] + high;
        z[8 + j] = (uint)product;
        high = (uint)(product >> 32);
    }
    z[7] = high;

    // Remaining rows
    #pragma unroll
    for (int i = 6; i >= 0; i--) {
        high = 0;
        #pragma unroll
        for (int j = 7; j >= 0; j--) {
            product = (uint64_t)x[i] * y[j] + z[i + j + 1] + high;
            z[i + j + 1] = (uint)product;
            high = (uint)(product >> 32);
        }
        z[i] = high;
    }

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out_high[i] = z[i];
        out_low[i]  = z[8 + i];
    }
}


/*===============================================================
 * Modular multiplication (hot path)
 * Optimized reduction for p = 2^256 - 2^32 - 977
 *===============================================================*/

void mulModP(const uint a[8], const uint b[8], uint product_low[8])
{
    uint high[8];
    uint hWord = 0;
    uint carry = 0;

    multiply256(a, b, high, product_low);

    // === Reduction stage 1: + 2^32 * high ===
    carry = 0;
    #pragma unroll
    for (int i = 6; i >= 0; i--) {
        product_low[i] = addc(product_low[i], high[i + 1], &carry);
    }
    uint product7 = addc(high[0], 0, &carry);
    uint product6 = carry;

    // === *977 ===
    carry = 0;
    hWord = 0;
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        uint t;
        madd977(&hWord, &t, high[i], hWord);
        product_low[i] = addc(product_low[i], t, &carry);
    }
    product7 = addc(product7, hWord, &carry);
    product6 = addc(product6, 0, &carry);

    // === Second reduction ===
    carry = 0;
    high[7] = product7;
    high[6] = product6;

    product_low[6] = addc(product_low[6], high[7], &carry);
    product_low[5] = addc(product_low[5], high[6], &carry);

    #pragma unroll
    for (int i = 4; i >= 0; i--) {
        product_low[i] = addc(product_low[i], 0, &carry);
    }
    product7 = carry;

    // final *977 of top words
    carry = 0;
    hWord = 0;
    uint t;
    madd977(&hWord, &t, high[7], hWord);
    product_low[7] = addc(product_low[7], t, &carry);
    madd977(&hWord, &t, high[6], hWord);
    product_low[6] = addc(product_low[6], t, &carry);
    product_low[5] = addc(product_low[5], hWord, &carry);

    #pragma unroll
    for (int i = 4; i >= 0; i--) {
        product_low[i] = addc(product_low[i], 0, &carry);
    }
    product7 = carry;

    // Final reduction
    if (product7 || greaterThanEqualToP(product_low)) {
        subP(product_low, product_low);
    }
}

uint256_t mulModP256k(uint256_t a, uint256_t b)
{
    uint256_t c;
    mulModP(a.v, b.v, c.v);
    return c;
}

uint256_t squareModP256k(uint256_t a)
{
    uint256_t b;
    mulModP(a.v, a.v, b.v);
    return b;
}


/*===============================================================
 * Modular inverse (Fermat) — addition chain
 *===============================================================*/

uint256_t invModP256k(uint256_t value)
{
    uint256_t x = value;
    uint256_t y = {{0, 0, 0, 0, 0, 0, 0, 1}};

    // 0xd
    y = mulModP256k(x, y); x = squareModP256k(x);
    x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);

    // 0x2
    x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);
    x = squareModP256k(x);
    x = squareModP256k(x);

    // 0xc
    x = squareModP256k(x);
    x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);

    // 0xfffff
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        y = mulModP256k(x, y);
        x = squareModP256k(x);
    }

    // 0xe
    x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);
    y = mulModP256k(x, y); x = squareModP256k(x);

    // remaining 219 bits
    for (int i = 0; i < 219; i++) {
        y = mulModP256k(x, y);
        x = squareModP256k(x);
    }
    y = mulModP256k(x, y);

    return y;
}


/*===============================================================
 * Batch inverse helpers (compatible with original)
 *===============================================================*/

void beginBatchAdd256k(uint256_t px, uint256_t x, __global uint256_t* chain, int i, int batchIdx, uint256_t* inverse)
{
    int gid = get_global_id(0);
    int dim = get_global_size(0);

    uint256_t t = subModP256k(px, x);
    *inverse = mulModP256k(*inverse, t);
    chain[batchIdx * dim + gid] = *inverse;
}

void beginBatchAddWithDouble256k(uint256_t px, uint256_t py, __global uint256_t* xPtr, __global uint256_t* chain, int i, int batchIdx, uint256_t* inverse)
{
    int gid = get_global_id(0);
    int dim = get_global_size(0);

    uint256_t x = xPtr[i];

    if (equal256k(px, x)) {
        x = addModP256k(py, py);
    } else {
        x = subModP256k(px, x);
    }

    *inverse = mulModP256k(x, *inverse);
    chain[batchIdx * dim + gid] = *inverse;
}

void completeBatchAddWithDouble256k(
    uint256_t px, uint256_t py,
    __global const uint256_t* xPtr, __global const uint256_t* yPtr,
    int i, int batchIdx,
    __global uint256_t* chain, uint256_t* inverse,
    uint256_t* newX, uint256_t* newY)
{
    int gid = get_global_id(0);
    int dim = get_global_size(0);

    uint256_t s, x, y;
    x = xPtr[i];
    y = yPtr[i];

    if (batchIdx >= 1) {
        uint256_t c = chain[(batchIdx - 1) * dim + gid];
        s = mulModP256k(*inverse, c);

        uint256_t diff = equal256k(px, x) ? addModP256k(py, py) : subModP256k(px, x);
        *inverse = mulModP256k(diff, *inverse);
    } else {
        s = *inverse;
    }

    if (equal256k(px, x)) {
        // Point doubling
        uint256_t x2 = mulModP256k(x, x);
        uint256_t tx2 = addModP256k(x2, x2);
        tx2 = addModP256k(x2, tx2);          // 3x²

        s = mulModP256k(tx2, s);             // λ = 3x² / 2y

        uint256_t s2 = mulModP256k(s, s);
        *newX = subModP256k(s2, x);
        *newX = subModP256k(*newX, x);

        uint256_t k = subModP256k(px, *newX);
        *newY = mulModP256k(s, k);
        *newY = subModP256k(*newY, py);
    } else {
        uint256_t rise = subModP256k(py, y);
        s = mulModP256k(rise, s);

        uint256_t s2 = mulModP256k(s, s);
        *newX = subModP256k(s2, px);
        *newX = subModP256k(*newX, x);

        uint256_t k = subModP256k(px, *newX);
        *newY = mulModP256k(s, k);
        *newY = subModP256k(*newY, py);
    }
}

void completeBatchAdd256k(
    uint256_t px, uint256_t py,
    __global uint256_t* xPtr, __global uint256_t* yPtr,
    int i, int batchIdx,
    __global uint256_t* chain, uint256_t* inverse,
    uint256_t* newX, uint256_t* newY)
{
    int gid = get_global_id(0);
    int dim = get_global_size(0);

    uint256_t s, x = xPtr[i];

    if (batchIdx >= 1) {
        uint256_t c = chain[(batchIdx - 1) * dim + gid];
        s = mulModP256k(*inverse, c);

        uint256_t diff = subModP256k(px, x);
        *inverse = mulModP256k(diff, *inverse);
    } else {
        s = *inverse;
    }

    uint256_t y = yPtr[i];
    uint256_t rise = subModP256k(py, y);
    s = mulModP256k(rise, s);

    uint256_t s2 = mulModP256k(s, s);
    *newX = subModP256k(s2, px);
    *newX = subModP256k(*newX, x);

    uint256_t k = subModP256k(px, *newX);
    *newY = mulModP256k(s, k);
    *newY = subModP256k(*newY, py);
}

uint256_t doBatchInverse256k(uint256_t x)
{
    return invModP256k(x);
}


/*===============================================================
 * Utility functions (kept for compatibility)
 *===============================================================*/

inline uint256_t readInt256(__global const uint256_t* ara, int idx)
{
    return ara[idx];
}

unsigned int readLSW(__global const unsigned int *ara, int idx)
{
    return ara[idx * 8 + 7];
}

unsigned int readLSW256k(__global const uint256_t* ara, int idx)
{
    return ara[idx].v[7];
}

unsigned int readWord256k(__global const uint256_t* ara, int idx, int word)
{
    return ara[idx].v[word];
}

void printBigInt(const unsigned int x[8])
{
    printf("%.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n",
           x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]);
}

#endif // _SECP256K1_CL