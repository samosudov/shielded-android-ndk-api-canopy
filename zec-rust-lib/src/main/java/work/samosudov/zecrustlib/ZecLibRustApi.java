package work.samosudov.zecrustlib;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import com.getkeepsafe.relinker.ReLinker;

import java.util.Arrays;


import work.samosudov.zecrustlib.crypto.Bech32;
import work.samosudov.zecrustlib.crypto.BitcoinCashBitArrayConverter;

import static work.samosudov.zecrustlib.crypto.Utils.bytesToHex;

public class ZecLibRustApi {

    public static void init(Context context) {
        ReLinker.Logger logcatLogger = new ReLinker.Logger() {
            @Override
            public void log(String message) {
                Log.d(RUST_INDEPENDENT_TAG,"ReLinker " + message);
            }
        };
        ReLinker.log(logcatLogger).loadLibrary(context, "native-lib-canopy");
    }

    //region NATIVE METHODS

    public static native String encryptNp(final byte[] key,
                                          final byte[] cipher);

    public static native byte[] cmRseed(final byte[] ivk,
                                          final byte[] plaintext);

    //endregion

    private final static String RUST_INDEPENDENT_TAG = "rust-independent";

}
