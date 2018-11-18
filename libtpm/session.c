/********************************************************************************/
/*										*/
/*			        TPM Session Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: session.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <tpmfunc.h>
#include <tpmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tpm_types.h>
#include <tpm_constants.h>

static uint32_t TPM_SaveContext_Internal(uint32_t handle,
                                         uint32_t resourceType,
                                         char* label,
                                         struct tpm_buffer* context,
                                         int allowTransport)
{
        uint32_t ret;
        uint32_t ordinal_no = htonl(TPM_ORD_SaveContext);

        STACK_TPM_BUFFER(tpmdata)
        uint32_t resourceType_no = htonl(resourceType);
        uint32_t handle_no = htonl(handle);
        uint32_t len;

        ret = TSS_buildbuff("00 c1 T l l l %",&tpmdata,
                            ordinal_no,
                            handle_no,
                            resourceType_no,
                            16, label);
        if ((ret  & ERR_MASK) != 0) {
                goto exit;
        }

        if (allowTransport)
                ret = TPM_Transmit(&tpmdata,"SaveContext");
        else
                ret = TPM_Transmit_NoTransport(&tpmdata, "SaveContext");

        if (0 != ret) {
                goto exit;
        }

        ret = tpm_buffer_load32(&tpmdata,
                                TPM_DATA_OFFSET,
                                &len);
        if ((ret & ERR_MASK)) {
                return ret;
        }

        if (context) {
                SET_TPM_BUFFER(context,
                               &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
                               len);
        }

        if (TPM_DATA_OFFSET + TPM_U32_SIZE + len != tpmdata.used) {
                printf("Something is wrong with the context blob!\n");
        }

exit:
        return ret;
}

uint32_t TPM_SaveContext_UseRoom(uint32_t handle,
                                 uint32_t resourceType,
                                 char* label,
                                 struct tpm_buffer* context)
{
        uint32_t ret;

        /*
         * Typically we would run the following code here:
         *
         * uint32_t replaced_keyhandle = 0;
         *
         * if (resourceType == TPM_RT_KEY) {
         *         ret = needKeysRoom_Stacked(handle, &replaced_keyhandle);
         *         if (ret != 0)
         *                 return ret;
         * }
         *
         * But that creates a lot of problems due to occurring recursion,
         * so for this comamnd we need to assume that the handle is
         * in the TPM at the moment.
         */ret = TPM_SaveContext_Internal(handle,
                                       resourceType,
                                       label,
                                       context,
                                       0);

        /*
         * Also don't need to do this here:
         *
         * if (resourceType == TPM_RT_KEY)
         *        needKeysRoom_Stacked_Undo(0, replaced_keyhandle);
         */return ret;
}

uint32_t TPM_SaveContext(uint32_t handle,
                         uint32_t resourceType,
                         char* label,
                         struct tpm_buffer* context)
{
        uint32_t ret;

        if (resourceType == TPM_RT_KEY) {
                ret = needKeysRoom(handle, 0, 0, 0);
                if (ret != 0)
                        return ret;
        }

        return TPM_SaveContext_Internal(handle,
                                        resourceType,
                                        label,
                                        context,
                                        1);
}

uint32_t TPM_LoadContext(uint32_t entityHandle,
                         TPM_BOOL keephandle,
                         struct tpm_buffer* context,
                         uint32_t* handle)
{
        uint32_t ret;
        uint32_t ordinal_no = htonl(TPM_ORD_LoadContext);

        STACK_TPM_BUFFER(tpmdata)
        uint32_t entityHandle_no = htonl(entityHandle);

        /*
         * must not call needKeysRoom from this function here
         * otherwise I might end up in an endless loop!!!
         */ret = TSS_buildbuff("00 c1 T l l o @",&tpmdata,
                            ordinal_no,
                            entityHandle_no,
                            keephandle,
                            context->used, context->buffer);
        if ((ret & ERR_MASK)) {
                goto exit;
        }

        ret = TPM_Transmit(&tpmdata,"LoadContext");

        if (0 != ret) {
                goto exit;
        }

        ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, handle);
exit:
        return ret;
}
