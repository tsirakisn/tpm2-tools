//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_errata.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "shared.h"

typedef struct tpm_create_ctx tpm_create_ctx;
struct tpm_create_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPM2B_SENSITIVE_CREATE in_sensitive;
    TPM2B_PUBLIC in_public;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMI_DH_OBJECT parent_handle;
    char *input;
    char *opu_path;
    char *opr_path;
    char *context_parent_path;
    TPMA_OBJECT objectAttributes;
    struct {
        UINT16 H : 1;
        UINT16 P : 1;
        UINT16 K : 1;
        UINT16 g : 1;
        UINT16 G : 1;
        UINT16 A : 1;
        UINT16 I : 1;
        UINT16 L : 1;
        UINT16 o : 1;
        UINT16 c : 1;
        UINT16 O : 1;
    } flags;
};

#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .objectAttributes = \
            TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_FIXEDTPM \
           |TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN \
           | TPMA_OBJECT_USERWITHAUTH \
        , \
    }, \
}

static tpm_create_ctx ctx = {
    .session_data = {
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
    },
    .type = TPM2_ALG_SHA1,
    .nameAlg = TPM2_ALG_RSA,
    .in_public = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT
};

int setup_alg()
{
    switch(ctx.nameAlg) {
    case TPM2_ALG_SHA1:
    case TPM2_ALG_SHA256:
    case TPM2_ALG_SHA384:
    case TPM2_ALG_SHA512:
    case TPM2_ALG_SM3_256:
    case TPM2_ALG_NULL:
        ctx.in_public.publicArea.nameAlg = ctx.nameAlg;
        break;
    default:
        LOG_ERR("nameAlg algorithm: 0x%0x not support !", ctx.nameAlg);
        return -1;
    }

    ctx.in_public.publicArea.type = ctx.type;

    switch(ctx.in_public.publicArea.type) {
    case TPM2_ALG_RSA:
        ctx.in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
        ctx.in_public.publicArea.parameters.rsaDetail.exponent = 0;
        ctx.in_public.publicArea.unique.rsa.size = 0;
        break;

    case TPM2_ALG_KEYEDHASH:
        ctx.in_public.publicArea.unique.keyedHash.size = 0;
        ctx.in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
        if (ctx.flags.I) {
            // sealing
            ctx.in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
            ctx.in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
            ctx.in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
        } else {
            // hmac
            ctx.in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
            ctx.in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
            ctx.in_public.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = ctx.nameAlg;  //for tpm2_hmac multi alg
        }
        break;

    case TPM2_ALG_ECC:
        ctx.in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        ctx.in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        ctx.in_public.publicArea.unique.ecc.x.size = 0;
        ctx.in_public.publicArea.unique.ecc.y.size = 0;
        break;

    case TPM2_ALG_SYMCIPHER:
        tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                          &ctx.in_public.publicArea.objectAttributes);

        ctx.in_public.publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
        ctx.in_public.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
        ctx.in_public.publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
        ctx.in_public.publicArea.unique.sym.size = 0;
        break;

    default:
        LOG_ERR("type algorithm: 0x%0x not support !", ctx.in_public.publicArea.type);
        return -2;
    }
    return 0;
}

int create_internal(TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_COMMAND sessionsData;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_PRIVATE           outPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;

    sessionsData.count = 1;
    sessionsData.auths[0] = ctx.session_data;

    ctx.in_sensitive.size = ctx.in_sensitive.sensitive.userAuth.size + 2;

    if(setup_alg())
        return -1;

    if (ctx.flags.A) {
        ctx.in_public.publicArea.objectAttributes = ctx.objectAttributes;
    }

    creationPCR.count = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, ctx.parent_handle, &sessionsData, &ctx.in_sensitive,
                           &ctx.in_public, &outsideInfo, &creationPCR, &outPrivate,&outPublic,
                           &creationData, &creationHash, &creationTicket, &sessionsDataOut));
    if(rval != TPM2_RC_SUCCESS) {
        LOG_ERR("\nCreate Object Failed ! ErrorCode: 0x%0x\n",rval);
        return -2;
    }

    tpm2_util_public_to_yaml(&outPublic);

    if (ctx.flags.o) {
        bool res = files_save_public(&outPublic, ctx.opu_path);
        if(!res) {
            return -3;
        }
    }

    if (ctx.flags.O) {
        bool res = files_save_private(&outPrivate, ctx.opr_path);
        if (!res) {
            return -4;
        }
    }

    return 0;
}

static bool load_sensitive(void) {

    ctx.in_sensitive.sensitive.data.size = BUFFER_SIZE(typeof(ctx.in_sensitive.sensitive.data), buffer);
    return files_load_bytes_from_file_or_stdin(ctx.input,
            &ctx.in_sensitive.sensitive.data.size, ctx.in_sensitive.sensitive.data.buffer);
}

// tpm2_create used to be a commandline tool, but now it's just a library.
// This wrapper allows us to build the tpm_create context from the args and
// skirt the new tpm2_tool option parsing scheme.
//
// Calls create_internal(), which was the original create()
// Note that some flags (e.g. P) are currently unused
int create(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT parent_handle, TPM2B_PUBLIC *in_public, TPM2B_SENSITIVE_CREATE *in_sensitive, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, char *input, char *opu_path, char *opr_path, int H_flag, int g_flag, int G_flag, int I_flag, int o_flag, int O_flag, int A_flag, TPMA_OBJECT objectAttributes) {

    ctx.parent_handle = parent_handle;
    ctx.in_public = *in_public;
    ctx.in_sensitive = *in_sensitive;
    ctx.type = type;
    ctx.nameAlg = nameAlg;
    ctx.input = input;
    ctx.opu_path = opu_path;
    ctx.opr_path = opr_path;
    ctx.objectAttributes = objectAttributes;
    ctx.flags.H = H_flag;
    ctx.flags.g = g_flag;
    ctx.flags.G = G_flag;
    ctx.flags.I = I_flag;
    ctx.flags.o = o_flag;
    ctx.flags.O = O_flag;
    ctx.flags.A = A_flag;

    // Everything below used to be tpm2_tool_onrun
    int returnVal = 0;
    int flagCnt = 0;

    if(ctx.flags.P == 0)
        ctx.session_data.hmac.size = 0;

    if (ctx.flags.I) {
        bool res = load_sensitive();
        if (!res) {
            return 1;
        }
    }

    if (ctx.flags.I && ctx.type != TPM2_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM2_ALG_KEYEDHASH algorithm is allowed when sealing data");
        return 1;
    }

    flagCnt = ctx.flags.H + ctx.flags.g + ctx.flags.G + ctx.flags.c;

    if(flagCnt == 1) {
        return 1;
    } else if(flagCnt == 3 && (ctx.flags.H == 1 || ctx.flags.c == 1) &&
              ctx.flags.g == 1 && ctx.flags.G == 1) {

        if(ctx.flags.c)
            returnVal = files_load_tpm_context_from_file(sapi_context,
                                                         &ctx.parent_handle, ctx.context_parent_path) != true;

        if(returnVal == 0)
            returnVal = create_internal(sapi_context);

        if(returnVal)
            return 1;
    } else {
        return 1;
    }

    return 0;
}
