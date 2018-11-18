/********************************************************************************/
/*										*/
/*			        TPM Key Handling Routines			*/
/*			     Written by J. Kravitz                              */
/*		       IBM Thomas J. Watson Research Center			*/
/*        $Id: keys.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#include <oiaposap.h>
#include <tpmfunc.h>
#include <tpmutil.h>
#include <tpmkeys.h>
#include <tpm_constants.h>
#include "tpm_error.h"
#include <hmac.h>
#include <serialize.h>

#include <gcrypt.h>


/****************************************************************************/
/*                                                                          */
/* Evict (delete) a  Key from the TPM                                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key to be evicted                         */
/*                                                                          */

/****************************************************************************/
static uint32_t TPM_EvictKey_Internal(uint32_t keyhandle, int allowTransport)
{
        uint32_t ret;

        STACK_TPM_BUFFER( tpmdata)
        char* version = getenv("TPM_VERSION");

        if (version == NULL || !strcmp("11",version)) {
                ret = TSS_buildbuff("00 c1 T 00 00 00 22 L",&tpmdata, keyhandle);
                if ((ret & ERR_MASK) != 0) return ret;
                /* transmit the request buffer to the TPM device and read the reply */
                if (allowTransport)
                        ret = TPM_Transmit(&tpmdata, "EvictKey");
                else
                        ret = TPM_Transmit_NoTransport(&tpmdata, "EvictKey");
                if (ret == TPM_BAD_ORDINAL) {
                        ret = TPM_FlushSpecific(keyhandle, TPM_RT_KEY);
                }
        } else {
                ret = TPM_FlushSpecific(keyhandle, TPM_RT_KEY);
        }
        return ret;
}

uint32_t TPM_EvictKey_UseRoom(uint32_t keyhandle)
{
        uint32_t ret;

        /*
         * To avoid recursion and major problems we assume for
         * this implementation here that the keyhandle is in
         * the TPM.
         *
         * uint32_t replaced_keyhandle;
         *
         * ret = needKeysRoom_Stacked(keyhandle, &replaced_keyhandle);
         * if (ret != 0)
         *        return 0;
         */ret = TPM_EvictKey_Internal(keyhandle, 0);

        /*
         * needKeysRoom_Stacked_Undo(0, replaced_keyhandle);
         */

        return ret;
}
