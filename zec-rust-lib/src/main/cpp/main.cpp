#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "zec_rust_lib.h"
#include "uint256.h"
#include "serialize.h"
#include "streams.h"
#include "version.h"
#include "zcash/IncrementalMerkleTree.hpp"

#include <jni.h>
#include <string>
#include <iostream>

#include <sys/mman.h>
#include <sstream>
#include <array>
#include <iomanip>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL
Java_work_samosudov_zecrustlib_ZecLibRustApi_genr(
        JNIEnv *env,
        jobject /* this */) {
    uint256 r;
    librustzcash_sapling_generate_r(r.begin());

    std::string strHex = r.GetHex();
    return env->NewStringUTF(strHex.c_str());
}

JNIEXPORT jstring JNICALL
Java_work_samosudov_zecrustlib_ZecLibRustApi_testUint256(
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


JNIEXPORT jbyteArray JNICALL
Java_work_samosudov_zecrustlib_ZecLibRustApi_merklePathToWitness(
        JNIEnv *env,
        jobject,
        jobjectArray authPathsArr,
        jbooleanArray indexesArr) {

    // Witness
    // 1. converting authPathsArr to std::vector
    std::vector<std::vector<bool>> authentication_path;

    int len1 = env -> GetArrayLength(authPathsArr);
    jbooleanArray dim=  (jbooleanArray)env->GetObjectArrayElement(authPathsArr, 0);
    int len2 = env -> GetArrayLength(dim);

    for(int i=0; i<len1; ++i){
        jbooleanArray oneDim= (jbooleanArray)env->GetObjectArrayElement(authPathsArr, i);
        jboolean *element=env->GetBooleanArrayElements(oneDim, 0);
        std::vector<bool> oneAuthVector;
        for(int j=0; j<len2; ++j) {
            oneAuthVector.push_back(element[j]);
        }
        authentication_path.push_back(oneAuthVector);
    }
    // 2. converting indexesArr to std::vector
    std::vector<bool> index;

    int len3 = env -> GetArrayLength(indexesArr);
    jboolean *element=env->GetBooleanArrayElements(indexesArr, 0);
    for(int i=0; i<len3; ++i){
        index.push_back(element[i]);
    }
    //3. serialize witness
    MerklePath merklePath = MerklePath(authentication_path, index);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << merklePath;
    std::vector<unsigned char> witness(ss.begin(), ss.end());

    //4. copy and return the witness
    int witness_size = witness.size();
    unsigned char* witness_array = new unsigned char[witness_size];

    std::copy(witness.begin(), witness.end(), witness_array);

    jbyteArray array = env->NewByteArray(witness_size);
    env->SetByteArrayRegion (array, 0, witness_size, reinterpret_cast<jbyte*>(witness_array));
    return array;
}

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_MAIN_H