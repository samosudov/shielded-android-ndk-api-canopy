extern crate jni;
extern crate libc;
extern crate rand;
extern crate blake2b_simd;
extern crate bls12_381;
extern crate byteorder;
extern crate crypto_api_chachapoly;
extern crate ff;
extern crate group;
extern crate rand_core;
extern crate jubjub;
extern crate zcash_primitives;
extern crate zcash_proofs;

use zcash_primitives::consensus::{self, BlockHeight, NetworkUpgrade::Canopy, ZIP212_GRACE_PERIOD, TEST_NETWORK};
use zcash_primitives::primitives::{Diversifier, Note, PaymentAddress, Rseed, ValueCommitment, ViewingKey, ProofGenerationKey};
use zcash_primitives::merkle_tree::{MerklePath};
use zcash_primitives::util::generate_random_rseed;
use zcash_primitives::keys::prf_expand;
use zcash_primitives::constants::{SPENDING_KEY_GENERATOR};

use zcash_proofs::prover::{LocalTxProver};

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crypto_api_chachapoly::{ChaCha20Ietf, ChachaPolyIetf};
use ff::{Field, PrimeField};
use group::{cofactor::CofactorGroup, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;
use std::fmt;
use std::str;

use std::io::{self, BufReader};
use std::ffi::CStr;

use libc::{c_char, c_uchar, int64_t, size_t, uint32_t, uint64_t};

use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring, JNI_FALSE, JNI_TRUE},
    JNIEnv,
};
use rand::{rngs::OsRng, Rng, SeedableRng, thread_rng};

const COMPACT_NOTE_SIZE: usize = 1 + // version
    11 + // diversifier
    8  + // value
    32; // rcv

static mut LOCAL_TX_PROVER: LocalTxProver = LocalTxProver::from_bytes(&[0u8], &[0u8]);

/// Return 32 byte random scalar, uniformly.
#[no_mangle]
pub extern "system" fn librustzcash_sapling_generate_r(result: *mut [c_uchar; 32]) {

    let result = unsafe { &mut *result };

}

#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_encryptNp(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    key: jbyteArray,
    cypher: jbyteArray,
) -> jstring {

            let key = env.convert_byte_array(key).unwrap();
            let cypher = env.convert_byte_array(cypher).unwrap();


            let output = env.new_string("spending_key hello")
                        .expect("Couldn't create java string!");

            output.into_inner()
}

/// Compute Sapling note commitment.
#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_cmRseed(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    ivk: jbyteArray,
    plaintext: jbyteArray,
    epk: jbyteArray
) -> jbyteArray {
    let ivk = env.convert_byte_array(ivk).unwrap();
    let plaintext = env.convert_byte_array(plaintext).unwrap();
    let epk = env.convert_byte_array(epk).unwrap();


    let mut ivk_array: [u8; 32] = [0; 32];
    ivk_array[..32].copy_from_slice(&ivk);
    let ivk_fs = jubjub::Fr::from_repr(ivk_array);

    let mut d = [0u8; 11];
    d.copy_from_slice(&plaintext[1..12]);

    let v = (&plaintext[12..20]).read_u64::<LittleEndian>();

    let mut r: [u8; 32] = [0u8; 32];
    r.copy_from_slice(&plaintext[20..COMPACT_NOTE_SIZE]);

    let rseed = if plaintext[0] == 0x01 {
        let rcm = jubjub::Fr::from_repr(r).unwrap();
        Rseed::BeforeZip212(rcm)
    } else {
        Rseed::AfterZip212(r)
    };

    let diversifier = Diversifier(d);

    let g_d = match diversifier.g_d() {
        Some(ret) => ret,
        _ => return env.byte_array_from_slice(&[0; 0]).expect("Could not convert u8 vec into java byte array!"),
    };
    let pk_d = g_d * ivk_fs.unwrap();

    let to = PaymentAddress::from_parts(diversifier, pk_d).unwrap();
    let note = to.create_note(v.unwrap(), rseed).unwrap();

    let cmu = note.cmu();
    let cmu_bytes = cmu.to_bytes();

    let mut epk_array: [u8; 32] = [0; 32];
    epk_array[..32].copy_from_slice(&epk);

    let derived_esk = note.derive_esk().unwrap();
    let note_derived_esk = (note.g_d * derived_esk).to_bytes();

    return if note_derived_esk == epk_array {
        env.byte_array_from_slice(&cmu_bytes).expect("Could not convert u8 vec into java byte array!")
    } else {
        env.byte_array_from_slice(&[0; 0]).expect("Could not convert u8 vec into java byte array!")
    }
}

/// Compute nullifier
#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_nullifier(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    ivk: jbyteArray,
    plaintext: jbyteArray,
    ak_jbytes: jbyteArray,
    nk_jbytes: jbyteArray,
    position_int: jint
) -> jbyteArray {
    let ivk_slice = env.convert_byte_array(ivk).unwrap();
    let plaintext = env.convert_byte_array(plaintext).unwrap();
    let ak_slice = env.convert_byte_array(ak_jbytes).unwrap();
    let nk_slice = env.convert_byte_array(nk_jbytes).unwrap();

    let mut ivk_array: [u8; 32] = [0; 32];
    ivk_array[..32].copy_from_slice(&ivk_slice);
    let ivk_fs = jubjub::Fr::from_repr(ivk_array);

    // AK
    let mut ak_bytes= [0u8; 32];
    ak_bytes[..32].copy_from_slice(&ak_slice);
    let ak = jubjub::SubgroupPoint::from_bytes(&ak_bytes).unwrap();

    // NK
    let mut nk_bytes = [0u8; 32];
    nk_bytes[..32].copy_from_slice(&nk_slice);
    let nk = jubjub::SubgroupPoint::from_bytes(&nk_bytes).unwrap();

    // D
    let mut d = [0u8; 11];
    d.copy_from_slice(&plaintext[1..12]);

    // V
    let v = (&plaintext[12..20]).read_u64::<LittleEndian>();

    // R
    let mut r: [u8; 32] = [0u8; 32];
    r.copy_from_slice(&plaintext[20..COMPACT_NOTE_SIZE]);

    let rseed = if plaintext[0] == 0x01 {
        let rcm = jubjub::Fr::from_repr(r).unwrap();
        Rseed::BeforeZip212(rcm)
    } else {
        Rseed::AfterZip212(r)
    };

    let diversifier = Diversifier(d);
    let pk_d = diversifier.g_d().unwrap() * ivk_fs.unwrap();

    // Address
    let to = PaymentAddress::from_parts(diversifier, pk_d).unwrap();
    // Note
    let note = to.create_note(v.unwrap(), rseed).unwrap();

    let vk = ViewingKey { ak, nk };

    let nf = note.nf(&vk, position_int as u64);
    let nf_bytes = nf.as_slice();

    env.byte_array_from_slice(&nf_bytes).expect("Could not convert u8 vec into java byte array!")
}

/// Convert pre Zip212 rcm to the new form
#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_convertRseed(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    rcm: jbyteArray
) -> jbyteArray {
    let rcm_slice = env.convert_byte_array(rcm).unwrap();

    let mut rcm_array: [u8; 32] = [0; 32];
    rcm_array[..32].copy_from_slice(&rcm_slice);

    let rcm_fr = jubjub::Fr::from_bytes_wide(prf_expand(&rcm_array, &[0x04]).as_array());
    let rcm_fr_bytes = rcm_fr.to_bytes();

    env.byte_array_from_slice(&rcm_fr_bytes).expect("Could not convert u8 vec into java byte array!")
}

/// Convert pre Zip212 esk to after Zip212 form
#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_convertEsk(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    esk: jbyteArray
) -> jbyteArray {
    let esk_slice = env.convert_byte_array(esk).unwrap();

    let mut esk_array: [u8; 32] = [0; 32];
    esk_array[..32].copy_from_slice(&esk_slice);

    let esk_fr = jubjub::Fr::from_bytes_wide(prf_expand(&esk_array, &[0x05]).as_array());
    let esk_fr_bytes = esk_fr.to_bytes();

    env.byte_array_from_slice(&esk_fr_bytes).expect("Could not convert u8 vec into java byte array!")
}

/// Generation a random Alpha parameter
#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_randomAlpha(
    env: JNIEnv<'_>,
    _: JClass<'_>
) -> jbyteArray {
    let mut rng = OsRng;
    let alpha_fr = jubjub::Fr::random(&mut rng);
    let alpha_fr_bytes = alpha_fr.to_bytes();

    env.byte_array_from_slice(&alpha_fr_bytes).expect("Could not convert u8 vec into java byte array!")
}

/// Initialization transaction prover with local param's files
#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_initTxProver(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    spend_bytes: jbyteArray,
    output_bytes: jbyteArray
) {
    let spend_param_bytes = env.convert_byte_array(spend_bytes).unwrap();
    let output_param_bytes = env.convert_byte_array(output_bytes).unwrap();

    unsafe {
        LOCAL_TX_PROVER = LocalTxProver::from_bytes(&spend_param_bytes, &output_param_bytes);
    }
}

/// Build transaction's spend proof
#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_zecrustlib_ZecLibRustApi_spendProof(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    ask_j_bytes: jbyteArray,
    nsk_j_bytes: jbyteArray,
    d_j_bytes: jbyteArray,
    r_j_bytes: jbyteArray,
    alpha_j_bytes: jbyteArray,
    value_j_long: jlong,
    anchor_j_bytes: jbyteArray,
    withess_j_bytes: jbyteArray,
) -> jbyteArray {
    let ask_bytes = env.convert_byte_array(ask_j_bytes).unwrap();
    let nsk_bytes = env.convert_byte_array(nsk_j_bytes).unwrap();
    let diversifier_bytes = env.convert_byte_array(d_j_bytes).unwrap();
    let r_bytes = env.convert_byte_array(r_j_bytes).unwrap();
    let alpha_bytes = env.convert_byte_array(alpha_j_bytes).unwrap();
    let anchor_bytes = env.convert_byte_array(anchor_j_bytes).unwrap();
    let withess_bytes = env.convert_byte_array(withess_j_bytes).unwrap();

    // Proving context
    let mut ctx = LOCAL_TX_PROVER.new_sapling_proving_context();

    // ProofGenerationKey
    let proof_generation_key = ProofGenerationKey {
        ak: SPENDING_KEY_GENERATOR * ask_bytes,
        nsk: nsk_bytes,
    };

    // Diversifier
    let mut diversifier_array: [u8; 11] = [0; 11];
    diversifier_array[..11].copy_from_slice(&diversifier_bytes);
    let diversifier = Diversifier(diversifier_array);

    // Rseed
    let mut r_array: [u8; 32] = [0; 32];
    r_array[..32].copy_from_slice(&r_bytes);
    let rseed = Rseed::AfterZip212(r_array);

    // Alpha
    let mut alpha_array: [u8; 32] = [0; 32];
    alpha_array[..32].copy_from_slice(&alpha_bytes);
    let alpha_fr = jubjub::Fr::from_bytes(&alpha_array);

    // Value
    let value = value_j_long as u64;

    // Anchor
    let anchor = bls12_381::Scalar::from_bytes(&anchor_bytes);

    // MarklePath
    let merkle_path = MerklePath::from_slice(withess_bytes);

    let (zkproof, cv, rk) = LOCAL_TX_PROVER
        .spend_proof(
            &mut ctx,
            proof_generation_key,
            diversifier,
            rseed,
            alpha_fr,
            value,
            anchor,
            merkle_path.clone(),
        );


    // TODO: compute returned value
    env.byte_array_from_slice(&[0; 32]).expect("Could not convert u8 vec into java byte array!")
}
