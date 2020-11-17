extern crate jni;
extern crate libc;
extern crate rand;
extern crate blake2b_simd;
extern crate byteorder;
extern crate crypto_api_chachapoly;
extern crate ff;
extern crate group;
extern crate rand_core;
extern crate jubjub;
extern crate zcash_client_backend;
// extern crate zcash_client_sqlite;
extern crate zcash_extensions;
extern crate zcash_history;
extern crate zcash_primitives;
extern crate zcash_proofs;

use zcash_primitives::consensus::{self, BlockHeight, NetworkUpgrade::Canopy, ZIP212_GRACE_PERIOD};
use zcash_primitives::primitives::{Diversifier, Note, PaymentAddress, Rseed};

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crypto_api_chachapoly::{ChaCha20Ietf, ChachaPolyIetf};
use ff::PrimeField;
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
use rand::{OsRng, Rand, Rng, SeedableRng, XorShiftRng, thread_rng};

const COMPACT_NOTE_SIZE: usize = 1 + // version
    11 + // diversifier
    8  + // value
    32; // rcv

/// Return 32 byte random scalar, uniformly.
#[no_mangle]
pub extern "system" fn librustzcash_sapling_generate_r(result: *mut [c_uchar; 32]) {
    // create random 64 byte buffer
    let mut rng = OsRng::new().expect("should be able to construct RNG");
    let mut buffer = [0u8; 32];

    let result = unsafe { &mut *result };
    for i in 0..result.len() {
        result[i] = rng.gen();
    }

}

#[no_mangle]
pub unsafe extern "C" fn Java_work_samosudov_rustlib_RustAPI_encryptNp(
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
pub unsafe extern "C" fn Java_work_samosudov_rustlib_RustAPI_cmRseed(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    ivk: jbyteArray,
    plaintext: jbyteArray
) -> jbyteArray {
    let ivk = env.convert_byte_array(ivk).unwrap();
    let plaintext = env.convert_byte_array(plaintext).unwrap();

    // assert_eq!(ivk.len(), 32);
    // assert_eq!(plaintext.len(), COMPACT_NOTE_SIZE);

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
    let pk_d = diversifier.g_d().unwrap() * ivk_fs.unwrap();

    let to = PaymentAddress::from_parts(diversifier, pk_d).unwrap();
    let note = to.create_note(v.unwrap(), rseed).unwrap();

    let cmu = note.cmu();
    let cmu_bytes = cmu.to_bytes();

    env.byte_array_from_slice(&cmu_bytes).expect("Could not convert u8 vec into java byte array!")
}
