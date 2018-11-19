/********************************************************************************/
/*										*/
/*			        TPM SEAL/UNSEAL routines			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: seal.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/*                                                                              */
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/*                                                                              */
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/*                                                                              */
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/*                                                                              */
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/*                                                                              */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <tpm.h>
#include <tpmutil.h>
#include <tpm_structures.h>
#include <tpmfunc.h>
#include <oiaposap.h>
#include <hmac.h>
#include <pcrs.h>

#define MAXPCRINFOLEN ((TPM_HASH_SIZE * 2) + TPM_U16_SIZE + TPM_PCR_MASK_SIZE)


/****************************************************************************/
/*                                                                          */
/* Unseal a data object                                                     */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/*           or NULL if no password is required                             */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           or NULL if no password is required                             */
/*           both authorization values must be 20 bytes long                */
/* blob      is a pointer to an area to containing the sealed blob          */
/* bloblen   is the length of the sealed blob                               */
/* rawdata   is a pointer to an area to receive the unsealed data (max 256?)*/
/* datalen   is a pointer to a int to receive the length of the data        */
/*                                                                          */

/****************************************************************************/
uint32_t TPM_Unseal(uint32_t keyhandle,
                    unsigned char* keyauth,
                    unsigned char* dataauth,
                    unsigned char* blob, uint32_t bloblen,
                    unsigned char* rawdata, uint32_t* datalen)
{
        uint32_t ret;

        STACK_TPM_BUFFER(tpmdata)
        unsigned char nonceodd[TPM_NONCE_SIZE];
        unsigned char dummyauth[TPM_NONCE_SIZE];
        unsigned char* passptr2;
        unsigned char c = 0;
        uint32_t ordinal = htonl(TPM_ORD_Unseal);
        uint32_t keyhndl = htonl(keyhandle);
        unsigned char authdata1[TPM_HASH_SIZE];
        unsigned char authdata2[TPM_HASH_SIZE];
        session sess;

        ret = needKeysRoom(keyhandle, 0, 0, 0);
        if (ret != 0) {
                return ret;
        }

        TSS_gennonce(nonceodd);
        memset(dummyauth,0,sizeof dummyauth);
        /* check input arguments */
        if (rawdata == NULL || blob == NULL) return ERR_NULL_ARG;
        if (dataauth == NULL) passptr2 = dummyauth;
        else passptr2 = dataauth;
        if (keyauth != NULL) /* key password specified */ {
                session sess2;
                unsigned char nonceodd2[TPM_NONCE_SIZE];

                TSS_gennonce(nonceodd2);

                /* open TWO OIAP sessions, one for the Key and one for the Data */
                ret = TSS_SessionOpen(SESSION_OSAP | SESSION_DSAP,
                                      &sess,
                                      keyauth, TPM_ET_KEYHANDLE, keyhandle);
                if (ret != 0)
                        return ret;

                ret = TSS_SessionOpen(SESSION_OIAP,
                                      &sess2,
                                      passptr2, 0, 0);
                if (ret != 0) {
                        TSS_SessionClose(&sess);
                        return ret;
                }
                /* calculate KEY authorization HMAC value */
                ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_NONCE_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
                                   TPM_U32_SIZE,&ordinal,
                                   bloblen,blob,
                                   0,0);
                if (ret != 0) {
                        TSS_SessionClose(&sess);
                        TSS_SessionClose(&sess2);

                        return ret;
                }
                /* calculate DATA authorization HMAC value */
                ret = TSS_authhmac(authdata2,TSS_Session_GetAuth(&sess2),TPM_NONCE_SIZE,/*enonce2*/ TSS_Session_GetENonce(&sess2),nonceodd2,c,
                                   TPM_U32_SIZE,&ordinal,
                                   bloblen,blob,
                                   0,0);
                if (ret != 0) {
                        TSS_SessionClose(&sess);
                        TSS_SessionClose(&sess2);
                        return ret;
                }
                /* build the request buffer */
                ret = TSS_buildbuff("00 C3 T l l % L % o % L % o %",&tpmdata,
                                    ordinal,
                                    keyhndl,
                                    bloblen,blob,
                                    TSS_Session_GetHandle(&sess),
                                    TPM_NONCE_SIZE,nonceodd,
                                    c,
                                    TPM_HASH_SIZE,authdata1,
                                    TSS_Session_GetHandle(&sess2),
                                    TPM_NONCE_SIZE,nonceodd2,
                                    c,
                                    TPM_HASH_SIZE,authdata2);

                if ((ret & ERR_MASK) != 0) {
                        TSS_SessionClose(&sess);
                        TSS_SessionClose(&sess2);
                        return ret;
                }
                /* transmit the request buffer to the TPM device and read the reply */
                ret = TPM_Transmit(&tpmdata,"Unseal - AUTH2");
                TSS_SessionClose(&sess);
                TSS_SessionClose(&sess2);

                if (ret != 0) {
                        return ret;
                }
                ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET,datalen);
                if ((ret & ERR_MASK)) {
                        return ret;
                }
                /* check HMAC in response */
                ret = TSS_checkhmac2(&tpmdata,ordinal,nonceodd,
                                     TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
                                     nonceodd2,
                                     TSS_Session_GetAuth(&sess2),TPM_HASH_SIZE,
                                     TPM_U32_SIZE,TPM_DATA_OFFSET,
                                     *datalen,TPM_DATA_OFFSET + TPM_U32_SIZE,
                                     0,0);
        } else /* no key password */ {
                /* open ONE OIAP session, for the Data */
                ret = TSS_SessionOpen(SESSION_OIAP,
                                      &sess,
                                      passptr2, 0, 0);
                if (ret != 0)
                        return ret;
                /* calculate DATA authorization HMAC value */
                ret = TSS_authhmac(authdata2,/*passptr2*/ TSS_Session_GetAuth(&sess),TPM_NONCE_SIZE,/*enonce2*/ TSS_Session_GetENonce(&sess),nonceodd,c,
                                   TPM_U32_SIZE,&ordinal,
                                   bloblen,blob,0,0);
                if (ret != 0) {
                        TSS_SessionClose(&sess);
                        return ret;
                }
                /* build the request buffer */
                ret = TSS_buildbuff("00 C2 T l l % L % o %",&tpmdata,
                                    ordinal,
                                    keyhndl,
                                    bloblen,blob,
                                    TSS_Session_GetHandle(&sess),
                                    TPM_NONCE_SIZE,nonceodd,
                                    c,
                                    TPM_HASH_SIZE,authdata2);

                if ((ret & ERR_MASK) != 0) {
                        TSS_SessionClose(&sess);
                        return ret;
                }
                /* transmit the request buffer to the TPM device and read the reply */
                ret = TPM_Transmit(&tpmdata,"Unseal - AUTH1");

                TSS_SessionClose(&sess);

                if (ret != 0) {
                        return ret;
                }
                ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, datalen);
                if ((ret & ERR_MASK)) {
                        return ret;
                }
                /* check HMAC in response */
                ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,
                                     TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
                                     TPM_U32_SIZE,TPM_DATA_OFFSET,
                                     *datalen,TPM_DATA_OFFSET + TPM_U32_SIZE,
                                     0,0);
        }
        if (ret != 0) {
                return ret;
        }
        /* copy decrypted data back to caller */
        memcpy(rawdata,
               &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
               *datalen);
        return ret;
}
