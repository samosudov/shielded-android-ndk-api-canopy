extern crate jni;
extern crate libc;
extern crate rand;

use std::io::{self, BufReader};
use std::ffi::CStr;

use libc::{c_char, c_uchar, int64_t, size_t, uint32_t, uint64_t};

use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring, JNI_FALSE, JNI_TRUE},
    JNIEnv,
};
use rand::{OsRng, Rand, Rng, SeedableRng, XorShiftRng, thread_rng};

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
