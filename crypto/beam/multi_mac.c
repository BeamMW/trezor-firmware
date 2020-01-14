#include "multi_mac.h"
#include "internal.h"

void multi_mac_reset(multi_mac_t *mm) {
  mm->n_casual = 0;
  mm->n_prepared = 0;
}

void multi_mac_with_bufs_alloc(multi_mac_t *mm, int max_casual,
                               int max_prepared) {
  multi_mac_reset(mm);
  UNUSED(max_casual);
  UNUSED(max_prepared);
//#if defined (LEDGER_SDK)
//#else
//  mm->casual = malloc(max_casual * sizeof(multi_mac_casual_t));
//  mm->prepared = malloc(max_prepared * sizeof(multi_mac_prepared_t *));
//  mm->k_prepared = malloc(max_prepared * sizeof(secp256k1_scalar));
//  mm->aux_prepared = malloc(max_prepared * sizeof(_multi_mac_fast_aux_t));
//#endif // LEDGER_SDK

}

void multi_mac_with_bufs_free(multi_mac_t *mm) {
  multi_mac_reset(mm);
//#if defined (LEDGER_SDK)
//#else
//  free(mm->casual);
//  free(mm->prepared);
//  free(mm->k_prepared);
//  free(mm->aux_prepared);
//#endif // LEDGER_SDK
}

void multi_mac_casual_init_new(multi_mac_casual_t *casual,
                               const secp256k1_gej *p) {
  casual->pt[1] = *p;
  casual->prepared = 1;
}

void multi_mac_casual_init(multi_mac_casual_t *casual, const secp256k1_gej *p,
                           const secp256k1_scalar *k) {
  multi_mac_casual_init_new(casual, p);
  casual->k = *k;
}

void multi_mac_fast_aux_schedule(_multi_mac_fast_aux_t *aux, const secp256k1_scalar *k,
                                 unsigned int iBitsRemaining,
                                 unsigned int nMaxOdd, unsigned int *pTbl,
                                 unsigned int iThisEntry) {
  const uint32_t *p = k->d;
  const uint32_t nWordBits = sizeof(*p) << 3;

  // assert(1 & nMaxOdd); // must be odd
  unsigned int nVal = 0, nBitTrg = 0;

  while (iBitsRemaining--) {
    nVal <<= 1;
    if (nVal > nMaxOdd) break;

    uint32_t n =
        p[iBitsRemaining / nWordBits] >> (iBitsRemaining & (nWordBits - 1));

    if (1 & n) {
      nVal |= 1;
      aux->odd = nVal;
      nBitTrg = iBitsRemaining;
    }
  }

  if (nVal > 0) {
    aux->next_item = pTbl[nBitTrg];
    pTbl[nBitTrg] = iThisEntry;
  }
}

void multi_mac_calculate(multi_mac_t *mm, secp256k1_gej *res) {
  printf("Multi mac calculate - enter\n");
  static const uint32_t nBytes = 32;
  static const uint32_t nBits = nBytes << 3;

  secp256k1_gej_set_infinity(res);

  unsigned int pTblCasual[nBits];
  unsigned int pTblPrepared[nBits];

  os_memset(pTblCasual, 0, sizeof(pTblCasual));
  os_memset(pTblPrepared, 0, sizeof(pTblPrepared));

  printf("About to prepared loop\n");
  for (size_t i = 0; i < mm->n_prepared; i++) {
    multi_mac_fast_aux_schedule(&mm->aux_prepared[i], &mm->k_prepared[i], nBits,
                                MULTI_MAC_PREPARED_MAX_ODD, pTblPrepared,
                                i + 1);
  }
  printf("About to casual loop\n");
  for (size_t i = 0; i < mm->n_casual; i++) {
    multi_mac_casual_t *x = &mm->casual[i];
    multi_mac_fast_aux_schedule(&x->aux, &x->k, nBits, MULTI_MAC_CASUAL_MAX_ODD,
                                pTblCasual, i + 1);
  }

  for (unsigned int iBit = nBits; iBit--;) {
    if (!secp256k1_gej_is_infinity(res))
      secp256k1_gej_double_var(res, res, NULL);

    while (pTblCasual[iBit]) {
      unsigned int iEntry = pTblCasual[iBit];
      multi_mac_casual_t *x = &mm->casual[iEntry - 1];
      pTblCasual[iBit] = x->aux.next_item;

      // assert(1 & m_Aux.odd);
      unsigned int nElem = (x->aux.odd >> 1) + 1;
      // assert(nElem < nCount);

      for (; x->prepared < nElem; x->prepared++) {
        if (1 == x->prepared)
          secp256k1_gej_double_var(&x->pt[0], &x->pt[1], NULL);
        secp256k1_gej_add_var(&x->pt[x->prepared + 1], &x->pt[x->prepared],
                              &x->pt[0], NULL);
      }
      secp256k1_gej_add_var(res, res, &x->pt[nElem], NULL);

      multi_mac_fast_aux_schedule(&x->aux, &x->k, iBit,
                                  MULTI_MAC_CASUAL_MAX_ODD, pTblCasual, iEntry);
    }

    while (pTblPrepared[iBit]) {
      unsigned int iEntry = pTblPrepared[iBit];
      _multi_mac_fast_aux_t *x = &mm->aux_prepared[iEntry - 1];
      pTblPrepared[iBit] = x->next_item;

      unsigned int nElem = (x->odd >> 1);

      secp256k1_gej_add_var(res, res, &mm->prepared[iEntry - 1].pt[nElem],
                            NULL);

      multi_mac_fast_aux_schedule(x, &mm->k_prepared[iEntry - 1], iBit,
                                  MULTI_MAC_PREPARED_MAX_ODD, pTblPrepared,
                                  iEntry);
    }
  }
}
