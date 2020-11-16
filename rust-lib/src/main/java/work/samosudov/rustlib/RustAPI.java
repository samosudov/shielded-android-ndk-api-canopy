package work.samosudov.rustlib;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import com.getkeepsafe.relinker.ReLinker;

import java.util.Arrays;


import work.samosudov.rustlib.crypto.Bech32;
import work.samosudov.rustlib.crypto.BitcoinCashBitArrayConverter;

import static work.samosudov.rustlib.crypto.Utils.bytesToHex;

public class RustAPI {

    public static void init(Context context) {
        ReLinker.Logger logcatLogger = new ReLinker.Logger() {
            @Override
            public void log(String message) {
                Log.d(RUST_INDEPENDENT_TAG,"ReLinker " + message);
            }
        };
        ReLinker.log(logcatLogger).loadLibrary(context, "native-lib");
    }

    //region NATIVE METHODS

    public static native String encryptNp(final byte[] key,
                                          final byte[] cipher);

    //endregion

    private final static String RUST_INDEPENDENT_TAG = "rust-independent";

}
