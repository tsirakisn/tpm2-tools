
//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// Copyright (c) 2017, Assured Information Security
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

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_mssim.h>
#include "pcr.h"
#include "log.h"
#include "tpm_session.h"
#include "tpm2_options.h"
#include "tpm2_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_alg_util.h"
#include "files.h"
#include "shared.h"

//Define the context object for tpm2_sealdata
typedef struct tpm_sealdata_ctx tpm_sealdata_ctx;
struct tpm_sealdata_ctx {
    TPMI_DH_OBJECT handle2048rsa;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMA_OBJECT objectAttributes;
    char * input;
    char * opu_path;
    char * opr_path;

    UINT32 pcr;
    INT32 pcrCount;
    pcr_struct* pcrList[24];
    BYTE forwardHash[32];
    bool hash_set;

    struct {
        UINT16 H : 1;
        UINT16 K : 1;
        UINT16 g : 1;
        UINT16 G : 1;
        UINT16 I : 1;
        UINT16 o : 1;
        UINT16 O : 1;
        UINT16 b : 1;
        UINT16 r : 1;
    } flags;
};

//Initialize the context object
static tpm_sealdata_ctx ctx = {
    .objectAttributes = 0,
    .opu_path = NULL,
    .opr_path = NULL,
    .pcr = -1,
    .pcrCount = 0,
    .hash_set = false,
    .forwardHash = {0}
};

int seal(TSS2_SYS_CONTEXT *sapi_context)
{
    UINT32 rval;
    SESSION *policySession;
    TPM2B_PUBLIC inPublic;
    TPM2B_DIGEST policyDigest;

    //Build a trial policy gated by the provided PCR
    rval = build_policy_external(sapi_context, &policySession, true, ctx.pcrList, ctx.pcrCount, &policyDigest, ctx.nameAlg);
    if(rval != TPM2_RC_SUCCESS) {
        LOG_ERR("build_policy failed, ec: 0x%x\n", rval);
        return rval;
    }

    inPublic.publicArea.authPolicy.size = policyDigest.size;
    memcpy(inPublic.publicArea.authPolicy.buffer, policyDigest.buffer, policyDigest.size);

    //Seal the provided data
    rval = create(sapi_context, ctx.handle2048rsa, &inPublic, &ctx.inSensitive, ctx.type, ctx.nameAlg, ctx.input, ctx.opu_path, ctx.opr_path, ctx.flags.H, ctx.flags.g, ctx.flags.G, ctx.flags.I, ctx.flags.o, ctx.flags.O, ctx.flags.b, ctx.objectAttributes);
    if(rval != TPM2_RC_SUCCESS) {
        LOG_ERR("create() failed, ec: 0x%x\n", rval);
        return rval;
    }

    return rval;

}

static bool on_option(char key, char *value) {

    ctx.inSensitive.sensitive.data.size = 0;

    switch (key) {
    case 'K':
        ctx.inSensitive.sensitive.userAuth.size = sizeof(ctx.inSensitive.sensitive.userAuth) - 2;
        if(tpm2_util_string_to_byte_structure(value, &ctx.inSensitive.sensitive.userAuth.size, ctx.inSensitive.sensitive.userAuth.buffer) != 0) {
            return false;
        }
        ctx.flags.K = 1;
        break;
    case 'g':
        ctx.nameAlg = tpm2_alg_util_from_optarg(value);
        if(ctx.nameAlg == TPM2_ALG_ERROR) {
            return false;
        }
        LOG_INFO("nameAlg = 0x%4.4x\n", ctx.nameAlg);
        ctx.flags.g = 1;
        break;
    case 'G':
        ctx.type = tpm2_alg_util_from_optarg(value);
        if(ctx.type == TPM2_ALG_ERROR) {
            return false;
        }
        LOG_INFO("type = 0x%4.4x\n", ctx.type);
        ctx.flags.G = 1;
        break;
    case 'b':
        if(!tpm2_attr_util_obj_from_optarg(value, &ctx.objectAttributes)) {
            return false;
        }
        ctx.flags.b = 1;
        break;
    case 'I':
        ctx.input = strcmp("-", value) ? value : NULL;
        ctx.flags.I = 1;
        LOG_INFO("ctx.inSensitive.sensitive.data.size = %d\n", ctx.inSensitive.sensitive.data.size);
        break;
    case 'o':
        ctx.opu_path = value;
        if(files_does_file_exist(ctx.opu_path) != 0) {
            return false;
        }
        ctx.flags.o = 1;
        break;
    case 'O':
        ctx.opr_path = value;
        //Allow output file to be overwritten
        ctx.flags.O = 1;
        break;
    case 'H':
        if (!tpm2_util_string_to_uint32(value, &ctx.handle2048rsa)) {
            LOG_ERR(
                    "Could not convert object handle to a number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.H = 1;
        break;
    case 'r':
        if ( pcr_parse_arg(value, &ctx.pcr, ctx.forwardHash, &ctx.hash_set) ) {
            LOG_ERR("Invalid pcr value.\n");
            return false;
        }
        pcr_struct *new_pcr = (pcr_struct *) malloc(sizeof(pcr_struct));
        new_pcr->pcr = ctx.pcr;
        new_pcr->hash_set = ctx.hash_set;
        memcpy(new_pcr->forwardHash, ctx.forwardHash, 32);
        memset(ctx.forwardHash, 0, 32);
        ctx.pcrList[ctx.pcrCount] = new_pcr;
        ctx.pcrCount++;

        ctx.flags.r = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      {"pwdk",             required_argument, NULL, 'K'},
      {"halg",             required_argument, NULL, 'g'},
      {"kalg",             required_argument, NULL, 'G'},
      {"objectAttributes", required_argument, NULL, 'b'},
      {"pcr",              required_argument, NULL, 'r'},
      {"inFile",           required_argument, NULL, 'I'},
      {"opu",              required_argument, NULL, 'o'},
      {"opr",              required_argument, NULL, 'O'},
      {"handle",           required_argument, NULL, 'H'}
    };

    *opts = tpm2_options_new("H:K:g:G:I:o:O:b:r:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int returnVal = 0;
    int flagCnt = 0;

    if(ctx.flags.K == 0)
        ctx.inSensitive.sensitive.userAuth.size = 0;

    flagCnt = ctx.flags.g + ctx.flags.G + ctx.flags.I + ctx.flags.r;
    if(flagCnt == 1) {
        returnVal = -16;
		goto out;
    } else if(flagCnt >= 4 && ctx.flags.I == 1 && ctx.flags.g == 1 && ctx.flags.G == 1 && ctx.flags.r == 1 && ctx.flags.H == 1) {
        if(returnVal == 0) {
            returnVal = seal(sapi_context);
        }

        if(returnVal) {
			goto out;
        }

        //clean up pcr objects
        for(int i = 0; i < ctx.pcrCount; i++)
            free(ctx.pcrList[i]);
    } else {
        returnVal = -18;
		goto out;
    }

out:
	//clean up handle
	if(Tss2_Sys_FlushContext(sapi_context, ctx.handle2048rsa) != TPM2_RC_SUCCESS)
            LOG_WARN("FlushContext failed for handle, non-fatal\n");
    return returnVal;
}

