package work.samosudov.zecrustlib;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.Uri;
import android.util.Log;

import com.getkeepsafe.relinker.ReLinker;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import static work.samosudov.zecrustlib.crypto.Utils.reverseByteArray;

public class ZecLibRustApi {

    public static void init(Context context) {
        ReLinker.Logger logcatLogger = new ReLinker.Logger() {
            @Override
            public void log(String message) {
                Log.d(ZEC_LIB_RUST_TAG,"ReLinker " + message);
            }
        };
        ReLinker.log(logcatLogger).loadLibrary(context, "native-lib-canopy");
    }

    //region NATIVE METHODS

    public static native String encryptNp(final byte[] key,
                                          final byte[] cipher);

    public static native byte[] cmRseed(final byte[] ivk,
                                        final byte[] plaintext,
                                        final byte[] epk);

    public static native byte[] nullifier(final byte[] ivk,
                                          final byte[] plaintext,
                                          final byte[] ak,
                                          final byte[] nk,
                                          final int position);

    public static native byte[] convertRseed(final byte[] rcm);
    public static native byte[] convertEsk(final byte[] esk);

    public static native byte[] randomAlpha();

    public static native byte[] initTxProver(final byte[] spendBytes,
                                           final byte[] outputBytes);

    public static native byte[] initTxProverFromPaths(final String spendPath,
                                                      final String outputPath);

    public static native String initTestString(final String spendPath);


    // C++ methods

    public static native byte[] merklePathToWitness(final boolean[][] authPathsArr,
                                                    final boolean[] indexesArr);


    //endregion

    private final static String ZEC_LIB_RUST_TAG = "zec-lib-rust";


    public static void initSaplingParams(AssetManager assetManager) {
        Log.d(ZEC_LIB_RUST_TAG, "initSaplingParams started");

        try {
            InputStream spendInputStream = assetManager.open("sapling-spend.params");
            InputStream outputInputStream = assetManager.open("sapling-output.params");

            byte[] spendBytes = new byte[spendInputStream.available()];
            byte[] outputBytes = new byte[outputInputStream.available()];

            BufferedInputStream bufferSpend = new BufferedInputStream(spendInputStream);
            BufferedInputStream bufferOutput = new BufferedInputStream(outputInputStream);
            bufferSpend.read(spendBytes, 0, spendBytes.length);
            bufferOutput.read(outputBytes, 0, outputBytes.length);
            bufferSpend.close();
            bufferOutput.close();

            byte[] res = initTxProver((spendBytes), (outputBytes));
            Log.d(ZEC_LIB_RUST_TAG, "initSaplingParams res: " + Arrays.toString(res));
        } catch (FileNotFoundException e) {
            Log.e(ZEC_LIB_RUST_TAG, "initSaplingParams FileNotFoundException: " + e.getMessage());
            e.printStackTrace();
        } catch (IOException e) {
            Log.e(ZEC_LIB_RUST_TAG, "initSaplingParams IOException: " + e.getMessage());
            e.printStackTrace();
        }

        Log.d(ZEC_LIB_RUST_TAG, "initSaplingParams done");
    }

    public static void initSaplingParamsFromPaths(Context context) {
        Log.d(ZEC_LIB_RUST_TAG, "initSaplingParamsFromPaths started");

        File cachedFileSpend = new File(context.getCacheDir(), "sapling-spend.params");
        File cachedFileOutput = new File(context.getCacheDir(), "sapling-output.params");

        try {
            InputStream spendInputStream = context.getAssets().open("sapling-spend.params");
            InputStream outputInputStream = context.getAssets().open("sapling-output.params");

            byte[] spendBytes = new byte[spendInputStream.available()];
            byte[] outputBytes = new byte[outputInputStream.available()];

            spendInputStream.read(spendBytes);
            outputInputStream.read(outputBytes);

            FileOutputStream paramSpendStream = new FileOutputStream(cachedFileSpend);
            FileOutputStream paramOutputStream = new FileOutputStream(cachedFileOutput);

            paramSpendStream.write(spendBytes);
            paramSpendStream.close();

            paramOutputStream.write(outputBytes);
            paramOutputStream.close();

            String spendPath = cachedFileSpend.getAbsolutePath();
            String outputPath = cachedFileOutput.getAbsolutePath();

            byte[] pathRes = initTxProverFromPaths(spendPath, outputPath);
            Log.d(ZEC_LIB_RUST_TAG, "initSaplingParamsFromPaths pathRes=" + Arrays.toString(pathRes));
        } catch (IOException e) {
            Log.e(ZEC_LIB_RUST_TAG, "initSaplingParamsFromPaths IOException: " + e.getMessage());
        }

        Log.d(ZEC_LIB_RUST_TAG, "initSaplingParamsFromPaths cachedFileSpend path=" + cachedFileSpend.getAbsolutePath());
        Log.d(ZEC_LIB_RUST_TAG, "initSaplingParamsFromPaths cachedFileOutput path=" + cachedFileOutput.getAbsolutePath());
        Log.d(ZEC_LIB_RUST_TAG, "initSaplingParamsFromPaths done");
    }

    public static void initTestFile(Context context) {
        Log.d(ZEC_LIB_RUST_TAG, "initTestFile started");

        File cachedFileSpend = new File(context.getCacheDir(), "test-file.params");

        try {
            InputStream spendInputStream = context.getAssets().open("test-file.params");

            byte[] spendBytes = new byte[spendInputStream.available()];
            spendInputStream.read(spendBytes);
            spendInputStream.close();

            FileOutputStream paramSpendStream = new FileOutputStream(cachedFileSpend);

            paramSpendStream.write(spendBytes);
            paramSpendStream.flush();
            paramSpendStream.close();

            String spendPath = cachedFileSpend.getAbsolutePath();

            String result = initTestString(spendPath);
            Log.d(ZEC_LIB_RUST_TAG, "initTestFile result=" + result);
        } catch (IOException e) {
            Log.e(ZEC_LIB_RUST_TAG, "initTestFile IOException: " + e.getMessage());
        }

        Log.d(ZEC_LIB_RUST_TAG, "initTestFile cachedFileSpend path=" + cachedFileSpend.getAbsolutePath());
        Log.d(ZEC_LIB_RUST_TAG, "initTestFile done");
    }

}
