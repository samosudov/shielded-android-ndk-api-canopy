#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "zapling_lib.h"
#include "uint256.h"
#include "serialize.h"
#include "version.h"
#include "streams.h"
#include "zcash/IncrementalMerkleTree.hpp"
#include "primitives/transaction.h"

#include <jni.h>
#include <string>
#include <iostream>

#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <android/sharedmem.h>
#include <sys/mman.h>
#include <sstream>
#include <array>
#include <iomanip>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL
Java_work_samosudov_rustlib_RustAPI_genr(
        JNIEnv *env,
        jobject /* this */) {
    uint256 r;
    librustzcash_sapling_generate_r(r.begin());

    std::string strHex = r.GetHex();
    return env->NewStringUTF(strHex.c_str());
}

JNIEXPORT jstring JNICALL
Java_work_samosudov_rustlib_RustAPI_testUint256(
        JNIEnv *env,
        jobject,
        jstring str) {

    // PKD to uint256
    std::string cpstr = env->GetStringUTFChars(str, NULL);
    uint256 res;
    res.SetHex(cpstr);

    std::string strHex = res.GetHex();
    return env->NewStringUTF(strHex.c_str());
}

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_MAIN_H