#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp> 
#include <boost/archive/iterators/transform_width.hpp> 
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include "ae.h"
#if defined(HAVE_STRINGS_H)
#include <strings.h>
#endif
#if defined(HAVE_ENDIAN_H)
#include <endian.h>
#elif defined(HAVE_SYS_ENDIAN_H)
#include <sys/types.h>
#include <sys/endian.h>
#endif
#include <openssl/aes.h>                            /* http://openssl.org/ */

#include "base64.h"
#include "fatal_assert.h"
#include "crypto.h"

using namespace std;
using namespace Crypto;
using namespace boost::archive::iterators;

#define L_TABLE_SZ          16
#define OCB_TAG_LEN         16
#define BPI                 4

#define DUMP_NAME_FMT "%-10s "

#define bswap32(x)                                              \
   ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
    (((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24))

// ocb.h\ocb.cc
static inline uint64_t bswap64(uint64_t x) {
    union { uint64_t u64; uint32_t u32[2]; } in, out;
    in.u64 = x;
    out.u32[0] = bswap32(in.u32[1]);
    out.u32[1] = bswap32(in.u32[0]);
    return out.u64;
}

static inline unsigned ntz(unsigned x) {
    static const unsigned char tz_table[32] =
    { 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
     31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9};
    return tz_table[((uint32_t)((x & -x) * 0x077CB531u)) >> 27];
}

typedef struct { uint64_t l,r; } block;
static inline block xor_block(block x, block y) {
    x.l^=y.l; x.r^=y.r; return x;
}
static inline block zero_block(void) { const block t = {0,0}; return t; }
#define unequal_blocks(x, y)         ((((x).l^(y).l)|((x).r^(y).r)) != 0)
static inline block swap_if_le(block b) {
    const union { unsigned x; unsigned char endian; } little = { 1 };
    if (little.endian) {
        block r;
        r.l = bswap64(b.l);
        r.r = bswap64(b.r);
        return r;
    } else
        return b;
}

#if __GNUC__ && !__clang__ && __arm__
static inline block double_block(block b) {
    __asm__ ("adds %1,%1,%1\n\t"
             "adcs %H1,%H1,%H1\n\t"
             "adcs %0,%0,%0\n\t"
             "adcs %H0,%H0,%H0\n\t"
             "it cs\n\t"
             "eorcs %1,%1,#135"
    : "+r"(b.l), "+r"(b.r) : : "cc");
    return b;
}
#else
static inline block double_block(block b) {
    uint64_t t = (uint64_t)((int64_t)b.l >> 63);
    b.l = (b.l + b.l) ^ (b.r >> 63);
    b.r = (b.r + b.r) ^ (t & 135);
    return b;
}
#endif

/* How to ECB encrypt an array of blocks, in place                         */
static inline void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
	while (nblks) {
		--nblks;
		AES_encrypt((unsigned char *)(blks+nblks), (unsigned char *)(blks+nblks), key);
	}
}

static inline void AES_ecb_decrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
	while (nblks) {
		--nblks;
		AES_decrypt((unsigned char *)(blks+nblks), (unsigned char *)(blks+nblks), key);
	}
}


struct _ae_ctx {
    block offset;                          /* Memory correct               */
    block checksum;                        /* Memory correct               */
    block Lstar;                           /* Memory correct               */
    block Ldollar;                         /* Memory correct               */
    block L[L_TABLE_SZ];                   /* Memory correct               */
    block ad_checksum;                     /* Memory correct               */
    block ad_offset;                       /* Memory correct               */
    block cached_Top;                      /* Memory correct               */
	uint64_t KtopStr[3];                   /* Register correct, each item  */
    uint32_t ad_blocks_processed;
    uint32_t blocks_processed;
    AES_KEY decrypt_key;
    AES_KEY encrypt_key;
    #if (OCB_TAG_LEN == 0)
    unsigned tag_len;
    #endif
};

static block getL(const ae_ctx *ctx, unsigned tz)
{
    if (tz < L_TABLE_SZ)
        return ctx->L[tz];
    else {
        unsigned i;
        /* Bring L[MAX] into registers, make it register correct */
        block rval = swap_if_le(ctx->L[L_TABLE_SZ-1]);
        rval = double_block(rval);
        for (i=L_TABLE_SZ; i < tz; i++)
            rval = double_block(rval);
        return swap_if_le(rval);             /* To memory correct */
    }
}

/* KtopStr is reg correct by 64 bits, return mem correct */
static block gen_offset(uint64_t KtopStr[3], unsigned bot) {
    block rval;
    if (bot != 0) {
        rval.l = (KtopStr[0] << bot) | (KtopStr[1] >> (64-bot));
        rval.r = (KtopStr[1] << bot) | (KtopStr[2] >> (64-bot));
    } else {
        rval.l = KtopStr[0];
        rval.r = KtopStr[1];
    }
    return swap_if_le(rval);
}

int ae_clear (ae_ctx *ctx) /* Zero ae_ctx and undo initialization          */
{
	memset(ctx, 0, sizeof(ae_ctx));
	return AE_SUCCESS;
}

int ae_ctx_sizeof(void) { return (int) sizeof(ae_ctx); }

int ae_init(ae_ctx *ctx, const void *key, int key_len, int nonce_len, int tag_len)
{
    unsigned i;
    block tmp_blk;

    if (nonce_len != 12)
    	return AE_NOT_SUPPORTED;

    /* Initialize encryption & decryption keys */
    #if (OCB_KEY_LEN > 0)
    key_len = OCB_KEY_LEN;
    #endif
    AES_set_encrypt_key((unsigned char *)key, key_len*8, &ctx->encrypt_key);
    #if USE_AES_NI
    AES_set_decrypt_key_fast(&ctx->decrypt_key,&ctx->encrypt_key);
    #else
    AES_set_decrypt_key((unsigned char *)key, (int)(key_len*8), &ctx->decrypt_key);
    #endif

    /* Zero things that need zeroing */
    ctx->cached_Top = ctx->ad_checksum = zero_block();
    ctx->ad_blocks_processed = 0;

    /* Compute key-dependent values */
    AES_encrypt((unsigned char *)&ctx->cached_Top,
                            (unsigned char *)&ctx->Lstar, &ctx->encrypt_key);
    tmp_blk = swap_if_le(ctx->Lstar);
    tmp_blk = double_block(tmp_blk);
    ctx->Ldollar = swap_if_le(tmp_blk);
    tmp_blk = double_block(tmp_blk);
    ctx->L[0] = swap_if_le(tmp_blk);
    for (i = 1; i < L_TABLE_SZ; i++) {
		tmp_blk = double_block(tmp_blk);
    	ctx->L[i] = swap_if_le(tmp_blk);
    }

    #if (OCB_TAG_LEN == 0)
    	ctx->tag_len = tag_len;
    #else
    	(void) tag_len;  /* Suppress var not used error */
    #endif

    return AE_SUCCESS;
}

static block gen_offset_from_nonce(ae_ctx *ctx, const void *nonce) {
	const union { unsigned x; unsigned char endian; } little = { 1 };
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
	unsigned idx;

	/* Replace cached nonce Top if needed */
	tmp.u32[0] = (little.endian?0x01000000:0x00000001);
	tmp.u32[1] = ((uint32_t *)nonce)[0];
	tmp.u32[2] = ((uint32_t *)nonce)[1];
	tmp.u32[3] = ((uint32_t *)nonce)[2];
	idx = (unsigned)(tmp.u8[15] & 0x3f);   /* Get low 6 bits of nonce  */
	tmp.u8[15] = tmp.u8[15] & 0xc0;        /* Zero low 6 bits of nonce */
	if ( unequal_blocks(tmp.bl,ctx->cached_Top) )   { /* Cached?       */
		ctx->cached_Top = tmp.bl;          /* Update cache, KtopStr    */
		// AES_encrypt(tmp.u8, (unsigned char *)&ctx->KtopStr, &ctx->encrypt_key);
		if (little.endian) {               /* Make Register Correct    */
			ctx->KtopStr[0] = bswap64(ctx->KtopStr[0]);
			ctx->KtopStr[1] = bswap64(ctx->KtopStr[1]);
		}
		ctx->KtopStr[2] = ctx->KtopStr[0] ^
						 (ctx->KtopStr[0] << 8) ^ (ctx->KtopStr[1] >> 56);
	}
	return gen_offset(ctx->KtopStr, idx);
}

static void process_ad(ae_ctx *ctx, const void *ad, int ad_len, int final)
{
    // this method is not used in fact.
    union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    block ad_offset, ad_checksum;
    const block *  adp = (block *)ad;
	unsigned i,k,tz,remaining;

    ad_offset = ctx->ad_offset;
    ad_checksum = ctx->ad_checksum;
    i = ad_len/(BPI*16);
    if (i) {
		unsigned ad_block_num = ctx->ad_blocks_processed;
		do {
			block ta[BPI], oa[BPI];
			ad_block_num += BPI;
			tz = ntz(ad_block_num);
			oa[0] = xor_block(ad_offset, ctx->L[0]);
			ta[0] = xor_block(oa[0], adp[0]);
			oa[1] = xor_block(oa[0], ctx->L[1]);
			ta[1] = xor_block(oa[1], adp[1]);
			oa[2] = xor_block(ad_offset, ctx->L[1]);
			ta[2] = xor_block(oa[2], adp[2]);
			#if BPI == 4
				ad_offset = xor_block(oa[2], getL(ctx, tz));
				ta[3] = xor_block(ad_offset, adp[3]);
			#elif BPI == 8
				oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(oa[3], adp[3]);
				oa[4] = xor_block(oa[1], ctx->L[2]);
				ta[4] = xor_block(oa[4], adp[4]);
				oa[5] = xor_block(oa[0], ctx->L[2]);
				ta[5] = xor_block(oa[5], adp[5]);
				oa[6] = xor_block(ad_offset, ctx->L[2]);
				ta[6] = xor_block(oa[6], adp[6]);
				ad_offset = xor_block(oa[6], getL(ctx, tz));
				ta[7] = xor_block(ad_offset, adp[7]);
			#endif
			AES_ecb_encrypt_blks(ta,BPI,&ctx->encrypt_key);
			ad_checksum = xor_block(ad_checksum, ta[0]);
			ad_checksum = xor_block(ad_checksum, ta[1]);
			ad_checksum = xor_block(ad_checksum, ta[2]);
			ad_checksum = xor_block(ad_checksum, ta[3]);
			#if (BPI == 8)
			ad_checksum = xor_block(ad_checksum, ta[4]);
			ad_checksum = xor_block(ad_checksum, ta[5]);
			ad_checksum = xor_block(ad_checksum, ta[6]);
			ad_checksum = xor_block(ad_checksum, ta[7]);
			#endif
			adp += BPI;
		} while (--i);
		ctx->ad_blocks_processed = ad_block_num;
		ctx->ad_offset = ad_offset;
		ctx->ad_checksum = ad_checksum;
	}

    if (final) {
		block ta[BPI];

        /* Process remaining associated data, compute its tag contribution */
        remaining = ((unsigned)ad_len) % (BPI*16);
        if (remaining) {
			k=0;
			#if (BPI == 8)
			if (remaining >= 64) {
				tmp.bl = xor_block(ad_offset, ctx->L[0]);
				ta[0] = xor_block(tmp.bl, adp[0]);
				tmp.bl = xor_block(tmp.bl, ctx->L[1]);
				ta[1] = xor_block(tmp.bl, adp[1]);
				ad_offset = xor_block(ad_offset, ctx->L[1]);
				ta[2] = xor_block(ad_offset, adp[2]);
				ad_offset = xor_block(ad_offset, ctx->L[2]);
				ta[3] = xor_block(ad_offset, adp[3]);
				remaining -= 64;
				k=4;
			}
			#endif
			if (remaining >= 32) {
				ad_offset = xor_block(ad_offset, ctx->L[0]);
				ta[k] = xor_block(ad_offset, adp[k]);
				ad_offset = xor_block(ad_offset, getL(ctx, ntz(k+2)));
				ta[k+1] = xor_block(ad_offset, adp[k+1]);
				remaining -= 32;
				k+=2;
			}
			if (remaining >= 16) {
				ad_offset = xor_block(ad_offset, ctx->L[0]);
				ta[k] = xor_block(ad_offset, adp[k]);
				remaining = remaining - 16;
				++k;
			}
			if (remaining) {
				ad_offset = xor_block(ad_offset,ctx->Lstar);
				tmp.bl = zero_block();
				memcpy(tmp.u8, adp+k, remaining);
				tmp.u8[remaining] = (unsigned char)0x80u;
				ta[k] = xor_block(ad_offset, tmp.bl);
				++k;
			}
			AES_ecb_encrypt_blks(ta,k,&ctx->encrypt_key);
			switch (k) {
				#if (BPI == 8)
				case 8: ad_checksum = xor_block(ad_checksum, ta[7]);
					/* fallthrough */
				case 7: ad_checksum = xor_block(ad_checksum, ta[6]);
					/* fallthrough */
				case 6: ad_checksum = xor_block(ad_checksum, ta[5]);
					/* fallthrough */
				case 5: ad_checksum = xor_block(ad_checksum, ta[4]);
					/* fallthrough */
				#endif
				case 4: ad_checksum = xor_block(ad_checksum, ta[3]);
					/* fallthrough */
				case 3: ad_checksum = xor_block(ad_checksum, ta[2]);
					/* fallthrough */
				case 2: ad_checksum = xor_block(ad_checksum, ta[1]);
					/* fallthrough */
				case 1: ad_checksum = xor_block(ad_checksum, ta[0]);
			}
			ctx->ad_checksum = ad_checksum;
		}
	}
}

static int constant_time_memcmp(const void *av, const void *bv, size_t n) {
    const uint8_t *a = (const uint8_t *) av;
    const uint8_t *b = (const uint8_t *) bv;
    uint8_t result = 0;
    size_t i;

    for (i=0; i<n; i++) {
        result |= *a ^ *b;
        a++;
        b++;
    }

    return (int) result;
}

int ae_encrypt(ae_ctx     *  ctx,
               const void *  nonce,
               const void *pt,
               int         pt_len,
               const void *ad,
               int         ad_len,
               void       *ct,
               void       *tag,
               int         final)
{
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    block offset, checksum;
    unsigned i, k;
    block       * ctp = (block *)ct;
    const block * ptp = (block *)pt;

    /* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        ctx->offset = gen_offset_from_nonce(ctx, nonce);
        ctx->ad_offset = ctx->checksum   = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        if (ad_len >= 0)
        	ctx->ad_checksum = zero_block();
    }

	/* Process associated data */
	if (ad_len > 0)
		process_ad(ctx, ad, ad_len, final);

	/* Encrypt plaintext data BPI blocks at a time */
    offset = ctx->offset;
    checksum  = ctx->checksum;
    i = pt_len/(BPI*16);
    if (i) {
    	block oa[BPI];
    	unsigned block_num = ctx->blocks_processed;
    	oa[BPI-1] = offset;
		do {
			block ta[BPI];
			block_num += BPI;
			oa[0] = xor_block(oa[BPI-1], ctx->L[0]);
			ta[0] = xor_block(oa[0], ptp[0]);
			checksum = xor_block(checksum, ptp[0]);
			oa[1] = xor_block(oa[0], ctx->L[1]);
			ta[1] = xor_block(oa[1], ptp[1]);
			checksum = xor_block(checksum, ptp[1]);
			oa[2] = xor_block(oa[1], ctx->L[0]);
			ta[2] = xor_block(oa[2], ptp[2]);
			checksum = xor_block(checksum, ptp[2]);
			#if BPI == 4
				oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
				ta[3] = xor_block(oa[3], ptp[3]);
				checksum = xor_block(checksum, ptp[3]);
			#elif BPI == 8
				oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(oa[3], ptp[3]);
				checksum = xor_block(checksum, ptp[3]);
				oa[4] = xor_block(oa[1], ctx->L[2]);
				ta[4] = xor_block(oa[4], ptp[4]);
				checksum = xor_block(checksum, ptp[4]);
				oa[5] = xor_block(oa[0], ctx->L[2]);
				ta[5] = xor_block(oa[5], ptp[5]);
				checksum = xor_block(checksum, ptp[5]);
				oa[6] = xor_block(oa[7], ctx->L[2]);
				ta[6] = xor_block(oa[6], ptp[6]);
				checksum = xor_block(checksum, ptp[6]);
				oa[7] = xor_block(oa[6], getL(ctx, ntz(block_num)));
				ta[7] = xor_block(oa[7], ptp[7]);
				checksum = xor_block(checksum, ptp[7]);
			#endif
			AES_ecb_encrypt_blks(ta,BPI,&ctx->encrypt_key);
			ctp[0] = xor_block(ta[0], oa[0]);
			ctp[1] = xor_block(ta[1], oa[1]);
			ctp[2] = xor_block(ta[2], oa[2]);
			ctp[3] = xor_block(ta[3], oa[3]);
			#if (BPI == 8)
			ctp[4] = xor_block(ta[4], oa[4]);
			ctp[5] = xor_block(ta[5], oa[5]);
			ctp[6] = xor_block(ta[6], oa[6]);
			ctp[7] = xor_block(ta[7], oa[7]);
			#endif
			ptp += BPI;
			ctp += BPI;
		} while (--i);
    	ctx->offset = offset = oa[BPI-1];
	    ctx->blocks_processed = block_num;
		ctx->checksum = checksum;
    }

    if (final) {
		block ta[BPI+1], oa[BPI];

        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = ((unsigned)pt_len) % (BPI*16);
        k = 0;                      /* How many blocks in ta[] need ECBing */
        if (remaining) {
			#if (BPI == 8)
			if (remaining >= 64) {
				oa[0] = xor_block(offset, ctx->L[0]);
				ta[0] = xor_block(oa[0], ptp[0]);
				checksum = xor_block(checksum, ptp[0]);
				oa[1] = xor_block(oa[0], ctx->L[1]);
				ta[1] = xor_block(oa[1], ptp[1]);
				checksum = xor_block(checksum, ptp[1]);
				oa[2] = xor_block(oa[1], ctx->L[0]);
				ta[2] = xor_block(oa[2], ptp[2]);
				checksum = xor_block(checksum, ptp[2]);
				offset = oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(offset, ptp[3]);
				checksum = xor_block(checksum, ptp[3]);
				remaining -= 64;
				k = 4;
			}
			#endif
			if (remaining >= 32) {
				oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block(oa[k], ptp[k]);
				checksum = xor_block(checksum, ptp[k]);
				offset = oa[k+1] = xor_block(oa[k], ctx->L[1]);
				ta[k+1] = xor_block(offset, ptp[k+1]);
				checksum = xor_block(checksum, ptp[k+1]);
				remaining -= 32;
				k+=2;
			}
			if (remaining >= 16) {
				offset = oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block(offset, ptp[k]);
				checksum = xor_block(checksum, ptp[k]);
				remaining -= 16;
				++k;
			}
			if (remaining) {
				tmp.bl = zero_block();
				memcpy(tmp.u8, ptp+k, remaining);
				tmp.u8[remaining] = (unsigned char)0x80u;
				checksum = xor_block(checksum, tmp.bl);
				ta[k] = offset = xor_block(offset,ctx->Lstar);
				++k;
			}
		}
        offset = xor_block(offset, ctx->Ldollar);      /* Part of tag gen */
        ta[k] = xor_block(offset, checksum);           /* Part of tag gen */
		AES_ecb_encrypt_blks(ta,k+1,&ctx->encrypt_key);
		offset = xor_block(ta[k], ctx->ad_checksum);   /* Part of tag gen */
		if (remaining) {
			--k;
			tmp.bl = xor_block(tmp.bl, ta[k]);
			memcpy(ctp+k, tmp.u8, remaining);
		}
		switch (k) {
			#if (BPI == 8)
			case 7: ctp[6] = xor_block(ta[6], oa[6]);
				/* fallthrough */
			case 6: ctp[5] = xor_block(ta[5], oa[5]);
				/* fallthrough */
			case 5: ctp[4] = xor_block(ta[4], oa[4]);
				/* fallthrough */
			case 4: ctp[3] = xor_block(ta[3], oa[3]);
				/* fallthrough */
			#endif
			case 3: ctp[2] = xor_block(ta[2], oa[2]);
				/* fallthrough */
			case 2: ctp[1] = xor_block(ta[1], oa[1]);
				/* fallthrough */
			case 1: ctp[0] = xor_block(ta[0], oa[0]);
		}

        /* Tag is placed at the correct location
         */
        if (tag) {
			#if (OCB_TAG_LEN == 16)
            	*(block *)tag = offset;
			#elif (OCB_TAG_LEN > 0)
	            memcpy((char *)tag, &offset, OCB_TAG_LEN);
			#else
	            memcpy((char *)tag, &offset, ctx->tag_len);
	        #endif
        } else {
			#if (OCB_TAG_LEN > 0)
	            memcpy((char *)ct + pt_len, &offset, OCB_TAG_LEN);
            	pt_len += OCB_TAG_LEN;
			#else
	            memcpy((char *)ct + pt_len, &offset, ctx->tag_len);
            	pt_len += ctx->tag_len;
	        #endif
        }
    }
    return (int) pt_len;
}

int ae_decrypt(ae_ctx     *ctx,
               const void *nonce,
               const void *ct,
               int         ct_len,
               const void *ad,
               int         ad_len,
               void       *pt,
               const void *tag,
               int         final)
{
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    block offset, checksum;
    unsigned i, k;
    block       *ctp = (block *)ct;
    block       *ptp = (block *)pt;

	/* Reduce ct_len tag bundled in ct */
	if ((final) && (!tag))
		#if (OCB_TAG_LEN > 0)
			ct_len -= OCB_TAG_LEN;
		#else
			ct_len -= ctx->tag_len;
		#endif

    /* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        ctx->offset = gen_offset_from_nonce(ctx, nonce);
        ctx->ad_offset = ctx->checksum   = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        if (ad_len >= 0)
        	ctx->ad_checksum = zero_block();
    }

	/* Process associated data */
	if (ad_len > 0)
		process_ad(ctx, ad, ad_len, final);

	/* Encrypt plaintext data BPI blocks at a time */
    offset = ctx->offset;
    checksum  = ctx->checksum;
    i = ct_len/(BPI*16);
    if (i) {
    	block oa[BPI];
    	unsigned block_num = ctx->blocks_processed;
    	oa[BPI-1] = offset;
		do {
			block ta[BPI];
			block_num += BPI;
			oa[0] = xor_block(oa[BPI-1], ctx->L[0]);
			ta[0] = xor_block(oa[0], ctp[0]);
			oa[1] = xor_block(oa[0], ctx->L[1]);
			ta[1] = xor_block(oa[1], ctp[1]);
			oa[2] = xor_block(oa[1], ctx->L[0]);
			ta[2] = xor_block(oa[2], ctp[2]);
			#if BPI == 4
				oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
				ta[3] = xor_block(oa[3], ctp[3]);
			#elif BPI == 8
				oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(oa[3], ctp[3]);
				oa[4] = xor_block(oa[1], ctx->L[2]);
				ta[4] = xor_block(oa[4], ctp[4]);
				oa[5] = xor_block(oa[0], ctx->L[2]);
				ta[5] = xor_block(oa[5], ctp[5]);
				oa[6] = xor_block(oa[7], ctx->L[2]);
				ta[6] = xor_block(oa[6], ctp[6]);
				oa[7] = xor_block(oa[6], getL(ctx, ntz(block_num)));
				ta[7] = xor_block(oa[7], ctp[7]);
			#endif
			AES_ecb_decrypt_blks(ta,BPI,&ctx->decrypt_key);
			ptp[0] = xor_block(ta[0], oa[0]);
			checksum = xor_block(checksum, ptp[0]);
			ptp[1] = xor_block(ta[1], oa[1]);
			checksum = xor_block(checksum, ptp[1]);
			ptp[2] = xor_block(ta[2], oa[2]);
			checksum = xor_block(checksum, ptp[2]);
			ptp[3] = xor_block(ta[3], oa[3]);
			checksum = xor_block(checksum, ptp[3]);
			#if (BPI == 8)
			ptp[4] = xor_block(ta[4], oa[4]);
			checksum = xor_block(checksum, ptp[4]);
			ptp[5] = xor_block(ta[5], oa[5]);
			checksum = xor_block(checksum, ptp[5]);
			ptp[6] = xor_block(ta[6], oa[6]);
			checksum = xor_block(checksum, ptp[6]);
			ptp[7] = xor_block(ta[7], oa[7]);
			checksum = xor_block(checksum, ptp[7]);
			#endif
			ptp += BPI;
			ctp += BPI;
		} while (--i);
    	ctx->offset = offset = oa[BPI-1];
	    ctx->blocks_processed = block_num;
		ctx->checksum = checksum;
    }

    if (final) {
		block ta[BPI+1], oa[BPI];

        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = ((unsigned)ct_len) % (BPI*16);
        k = 0;                      /* How many blocks in ta[] need ECBing */
        if (remaining) {
			#if (BPI == 8)
			if (remaining >= 64) {
				oa[0] = xor_block(offset, ctx->L[0]);
				ta[0] = xor_block(oa[0], ctp[0]);
				oa[1] = xor_block(oa[0], ctx->L[1]);
				ta[1] = xor_block(oa[1], ctp[1]);
				oa[2] = xor_block(oa[1], ctx->L[0]);
				ta[2] = xor_block(oa[2], ctp[2]);
				offset = oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(offset, ctp[3]);
				remaining -= 64;
				k = 4;
			}
			#endif
			if (remaining >= 32) {
				oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block(oa[k], ctp[k]);
				offset = oa[k+1] = xor_block(oa[k], ctx->L[1]);
				ta[k+1] = xor_block(offset, ctp[k+1]);
				remaining -= 32;
				k+=2;
			}
			if (remaining >= 16) {
				offset = oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block(offset, ctp[k]);
				remaining -= 16;
				++k;
			}
			if (remaining) {
				block pad;
				offset = xor_block(offset,ctx->Lstar);
				AES_encrypt((unsigned char *)&offset, tmp.u8, &ctx->encrypt_key);
				pad = tmp.bl;
				memcpy(tmp.u8,ctp+k,remaining);
				tmp.bl = xor_block(tmp.bl, pad);
				tmp.u8[remaining] = (unsigned char)0x80u;
				memcpy(ptp+k, tmp.u8, remaining);
				checksum = xor_block(checksum, tmp.bl);
			}
		}
		AES_ecb_decrypt_blks(ta,k,&ctx->decrypt_key);
		switch (k) {
			#if (BPI == 8)
			case 7: ptp[6] = xor_block(ta[6], oa[6]);
				    checksum = xor_block(checksum, ptp[6]);
				    /* fallthrough */
			case 6: ptp[5] = xor_block(ta[5], oa[5]);
				    checksum = xor_block(checksum, ptp[5]);
				    /* fallthrough */
			case 5: ptp[4] = xor_block(ta[4], oa[4]);
				    checksum = xor_block(checksum, ptp[4]);
				    /* fallthrough */
			case 4: ptp[3] = xor_block(ta[3], oa[3]);
				    checksum = xor_block(checksum, ptp[3]);
				    /* fallthrough */
			#endif
			case 3: ptp[2] = xor_block(ta[2], oa[2]);
				    checksum = xor_block(checksum, ptp[2]);
				    /* fallthrough */
			case 2: ptp[1] = xor_block(ta[1], oa[1]);
				    checksum = xor_block(checksum, ptp[1]);
				    /* fallthrough */
			case 1: ptp[0] = xor_block(ta[0], oa[0]);
				    checksum = xor_block(checksum, ptp[0]);
		}

		/* Calculate expected tag */
        offset = xor_block(offset, ctx->Ldollar);
        tmp.bl = xor_block(offset, checksum);
		AES_encrypt(tmp.u8, tmp.u8, &ctx->encrypt_key);
		tmp.bl = xor_block(tmp.bl, ctx->ad_checksum); /* Full tag */

		/* Compare with proposed tag, change ct_len if invalid */
		if ((OCB_TAG_LEN == 16) && tag) {
			if (unequal_blocks(tmp.bl, *(block *)tag))
				ct_len = AE_INVALID;
		} else {
			#if (OCB_TAG_LEN > 0)
				int len = OCB_TAG_LEN;
			#else
				int len = ctx->tag_len;
			#endif
			if (tag) {
				if (constant_time_memcmp(tag,tmp.u8,len) != 0)
					ct_len = AE_INVALID;
			} else {
				if (constant_time_memcmp((char *)ct + ct_len,tmp.u8,len) != 0)
					ct_len = AE_INVALID;
			}
		}
    }
    return ct_len;
 }

// base64 enconding
static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char reverse_mosh[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
  0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
  0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* Reverse maps from an ASCII char to a base64 sixbit value.  Returns > 0x3f on failure. */
static unsigned char base64_char_to_sixbit(unsigned char c)
{
  return reverse_mosh[c];
}

bool base64_decode_mosh( const char *b64, const size_t b64_len,
		    uint8_t *raw, size_t *raw_len )
{
  fatal_assert( b64_len == 24 ); /* only useful for Mosh keys */
  fatal_assert( *raw_len == 16 );

  uint32_t bytes = 0;
  for (int i = 0; i < 22; i++) {
    unsigned char sixbit = base64_char_to_sixbit(*(b64++));
    if (sixbit > 0x3f) {
      return false;
    }
    bytes <<= 6;
    bytes |= sixbit;
    /* write groups of 3 */
    if (i % 4 == 3) {
      raw[0] = bytes >> 16;
      raw[1] = bytes >> 8;
      raw[2] = bytes;
      raw += 3;
      bytes = 0;
    }
  }
  /* last byte of output */
  *raw = bytes >> 4;
  if (b64[0] != '=' || b64[1] != '=') {
    return false;
  }
  return true;
}

void base64_encode_mosh( const uint8_t *raw, const size_t raw_len,
		    char *b64, const size_t b64_len )
{
  fatal_assert( b64_len == 24 ); /* only useful for Mosh keys */
  fatal_assert( raw_len == 16 );

  /* first 15 bytes of input */
  for (int i = 0; i < 5; i++) {
    uint32_t bytes = (raw[0] << 16) | (raw[1] << 8) | raw[2];
    b64[0] = table[(bytes >> 18) & 0x3f];
    b64[1] = table[(bytes >> 12) & 0x3f];
    b64[2] = table[(bytes >> 6) & 0x3f];
    b64[3] = table[(bytes) & 0x3f];
    raw += 3;
    b64 += 4;
  }

  /* last byte of input, last 4 of output */
  uint8_t lastchar = *raw;
  b64[0] = table[(lastchar >> 2) & 0x3f];
  b64[1] = table[(lastchar << 4) & 0x3f];
  b64[2] = '=';
  b64[3] = '=';
}

bool Base64Decode(const std::string& input, std::string* output) {
	typedef boost::archive::iterators::transform_width<boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6> Base64DecodeIterator;
	std::stringstream result;
	try {
		copy(Base64DecodeIterator(input.begin()), Base64DecodeIterator(input.end()), ostream_iterator<char>(result));
	}
	catch (...) {
		return false;
	}
	*output = result.str();
	return output->empty() == false;
}

// crypto.h\crypto.cc
AlignedBuffer::AlignedBuffer( size_t len, const char *data )
  : m_len( len ), m_allocated( NULL ), m_data( NULL )
{
  size_t alloc_len = len ? len : 1;
#if defined(HAVE_POSIX_MEMALIGN)
  if ( ( 0 != posix_memalign( &m_allocated, 16, alloc_len ) )
      || ( m_allocated == NULL ) ) {
    throw std::bad_alloc();
  }
  m_data = (char *) m_allocated;

#else
  /* malloc() a region 15 bytes larger than we need, and find
     the aligned offset within. */
  m_allocated = malloc( 15 + alloc_len );
  if ( m_allocated == NULL ) {
    throw std::bad_alloc();
  }

  uintptr_t iptr = (uintptr_t) m_allocated;
  if ( iptr & 0xF ) {
    iptr += 16 - ( iptr & 0xF );
  }

  m_data = (char *) iptr;

#endif /* !defined(HAVE_POSIX_MEMALIGN) */

  if ( data ) {
    memcpy( m_data, data, len );
  }
}

Base64Key::Base64Key( string printable_key )
{
  if ( printable_key.length() != 22 ) {
    throw CryptoException( "Key must be 22 letters long." );
  }

  string base64 = printable_key + "==";

  size_t len = 16;
  if ( !base64_decode_mosh( base64.data(), 24, key, &len ) ) {
    throw CryptoException( "Key must be well-formed base64." );
  }

  if ( len != 16 ) {
    throw CryptoException( "Key must represent 16 octets." );
  }

  /* to catch changes after the first 128 bits */
  if ( printable_key != this->printable_key() ) {
    throw CryptoException( "Base64 key was not encoded 128-bit key." );
  }
}

string Base64Key::printable_key( void ) const
{
  char base64[ 24 ];

  base64_encode_mosh( key, 16, base64, 24 );

  if ( (base64[ 23 ] != '=')
       || (base64[ 22 ] != '=') ) {
    throw CryptoException( string( "Unexpected output from base64_encode: " ) + string( base64, 24 ) );
  }

  base64[ 22 ] = 0;
  return string( base64 );
}

Session::Session( Base64Key s_key )
  : key( s_key ), ctx_buf( ae_ctx_sizeof() ),
    ctx( (ae_ctx *)ctx_buf.data() ), blocks_encrypted( 0 ),
    plaintext_buffer( RECEIVE_MTU ),
    ciphertext_buffer( RECEIVE_MTU ),
    nonce_buffer( Nonce::NONCE_LEN )
{
  if ( AE_SUCCESS != ae_init( ctx, key.data(), 16, 12, 16 ) ) {
    throw CryptoException( "Could not initialize AES-OCB context." );
  }
}

Session::~Session()
{
  fatal_assert( ae_clear( ctx ) == AE_SUCCESS );
}

Nonce::Nonce( uint64_t val )
{
  uint64_t val_net = htobe64( val );

  memset( bytes, 0, 4 );
  memcpy( bytes + 4, &val_net, 8 );
}

uint64_t Nonce::val( void ) const
{
  uint64_t ret;
  memcpy( &ret, bytes + 4, 8 );
  return be64toh( ret );
}

Nonce::Nonce( const char *s_bytes, size_t len )
{
  if ( len != 8 ) {
    throw CryptoException( "Nonce representation must be 8 octets long." );
  }

  memset( bytes, 0, 4 );
  memcpy( bytes + 4, s_bytes, 8 );
}

const string Session::encrypt( const Message & plaintext )
{
  const size_t pt_len = plaintext.text.size();
  const int ciphertext_len = pt_len + 16;

  assert( (size_t)ciphertext_len <= ciphertext_buffer.len() );
  assert( pt_len <= plaintext_buffer.len() );

  memcpy( plaintext_buffer.data(), plaintext.text.data(), pt_len );
  memcpy( nonce_buffer.data(), plaintext.nonce.data(), Nonce::NONCE_LEN );

  if ( ciphertext_len != ae_encrypt( ctx,                                     /* ctx */
				     nonce_buffer.data(),                     /* nonce */
				     plaintext_buffer.data(),                 /* pt */
				     pt_len,                                  /* pt_len */
				     NULL,                                    /* ad */
				     0,                                       /* ad_len */
				     ciphertext_buffer.data(),                /* ct */
				     NULL,                                    /* tag */
				     AE_FINALIZE ) ) {                        /* final */
    throw CryptoException( "ae_encrypt() returned error." );
  }

  blocks_encrypted += pt_len >> 4;
  if ( pt_len & 0xF ) {
    /* partial block */
    blocks_encrypted++;
  }

  /* "Both the privacy and the authenticity properties of OCB degrade as
      per s^2 / 2^128, where s is the total number of blocks that the
      adversary acquires.... In order to ensure that s^2 / 2^128 remains
      small, a given key should be used to encrypt at most 2^48 blocks (2^55
      bits or 4 petabytes)"

     -- http://tools.ietf.org/html/draft-krovetz-ocb-03

     We deem it unlikely that a legitimate user will send 4 PB through a Mosh
     session.  If it happens, we simply kill the session.  The server and
     client use the same key, so we actually need to die after 2^47 blocks.
  */
  if ( blocks_encrypted >> 47 ) {
    throw CryptoException( "Encrypted 2^47 blocks.", true );
  }

  string text( ciphertext_buffer.data(), ciphertext_len );

  return plaintext.nonce.cc_str() + text;
}

const Message Session::decrypt( const char *str, size_t len )
{
  if ( len < 24 ) {
    throw CryptoException( "Ciphertext must contain nonce and tag." );
  }

  int body_len = len - 8;
  int pt_len = body_len - 16;

  if ( pt_len < 0 ) { /* super-assertion that pt_len does not equal AE_INVALID */
    fprintf( stderr, "BUG.\n" );
    exit( 1 );
  }

  Nonce nonce( str, 8 );
  memcpy( ciphertext_buffer.data(), str + 8, body_len );
  memcpy( nonce_buffer.data(), nonce.data(), Nonce::NONCE_LEN );

  if ( pt_len != ae_decrypt( ctx,                      /* ctx */
			     nonce_buffer.data(),      /* nonce */
			     ciphertext_buffer.data(), /* ct */
			     body_len,                 /* ct_len */
			     NULL,                     /* ad */
			     0,                        /* ad_len */
			     plaintext_buffer.data(),  /* pt */
			     NULL,                     /* tag */
			     AE_FINALIZE ) ) {         /* final */
    throw CryptoException( "Packet failed integrity check." );
  }

  const Message ret( nonce, string( plaintext_buffer.data(), pt_len ) );

  return ret;
}

void hexdump( const void *buf, size_t len, const char *name ) {
  const unsigned char *data = (const unsigned char *) buf;
  printf( DUMP_NAME_FMT, name );
  for ( size_t i = 0; i < len; i++ ) {
    printf( "%02x", data[ i ] );
  }
  printf( "\n" );
}

void hexdump( const std::string &buf, const char *name ) {
  hexdump( buf.data(), buf.size(), name );
}

int main(int argc, const char** argv) {
	const union { unsigned x; unsigned char endian; } little = { 1 };
    if (little.endian) {
        cout << "Litter endian." << endl;
    }
    string base64 = "4UVV8YWRGg1kBxAlhQ09ZA";
    // string content = "gAAAAAAAAACnDqhhT8z2XVfl8gawHl5NFG3opTmDxEvxLE92qegsXJQFJT/bTHSBb0GiGxDNO632pci7vW+bZ7gy1+250WcSsl2dBC79wrv+K002cgnY+OptLqOnM7PUAUNwHmOplCR/HZ8D0zgrIIYPWP8UFVqFhwi4cu9/rYMDZbMMwZuVUJKRjRuHOfx6CW8cw9gY2Q==";
    string content = "gAAAAAAAAAUGgH9dvmmt+jBp6WwNCx2Wb52S+ZpnTFKdkmZEUdrRPbei/eosmmaUF9uorZufiDke8e2x1J/d1Las6Pc188tvnS1nyEpkvBkbg7JDFyxByV355LqL1oRwwpQn64elhjhqtSk559AI06qMe/V8vM6WfrbECAwnuR5COUF7dGV6Us1RoIOAr4V/+JBIfoFrozJnEg==";
    string src;
    bool suc = Base64Decode(content, &src);
    src = src.substr(0, src.size() - 2);
    if (suc) {
        cout << "Base64 decode content success." << endl;
        for (int i = 0; i < src.size(); i++) {
            printf("%d ", src.data()[i]);
        }
        cout << endl;
    } else {
        throw CryptoException( "Base64 decode content failed." );
    }

    // hexdump(src, "ct");

    Base64Key key(base64);
    Session session(key);

    try {
        session.decrypt(src);
    } catch ( const CryptoException &e ) {
        cout << "CryptoExcetion catched." << endl;
        /* The "bad decrypt" exception needs to be non-fatal, otherwise we are
        vulnerable to an easy DoS. */
        fatal_assert( ! e.fatal );
    }
}

