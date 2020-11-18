package work.samosudov.zecrustlib

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import work.samosudov.zecrustlib.crypto.Utils
import work.samosudov.zecrustlib.crypto.Utils.*
import java.util.*

class ZecLibRustApiTest {

    companion object {
        val note = byteArrayOf(1, 49, -56, 16, 72, -122, 103, 46, 68, 17, 99, 117, -96, 105, 117, 0, 0, 0, 0, 0, 76, -96, 22, 106, 90, -59, 124, 1, -55, 48, 96, 10, -60, 49, -63, 1, 15, -41, -72, -75, -104, -57, 42, 47, 3, 54, -24, -65, -62, -52, 77, 14)
        val key = byteArrayOf(69, 121, -20, 127, -124, -3, 114, -88, 7, -102, 47, 22, -12, -31, -92, -93, -41, 62, 32, -6, -80, -24, 115, 22, 115, -83, -91, -43, 98, 103, -54, -15)
        val ivk = hexToBytes("00c11ba0a37371bd41ba456fb95d36c09b55d2ac9fa9e62bc71d1b08d3bc78b4")
        val ivkSecond = hexToBytes("0305649e356eb65e0e0ac758e9d429d8e0d88d3a88a7bc9d07ce792d7e315442")
        val plainText = byteArrayOf(2, 107, 32, 71, -62, -6, 78, -7, -113, -2, -91, 59, -110, -53, 62, 53, -47, -37, 86, 61, -86, 116, -58, -116, -110, 68, -91, 5, -64, 90, 106, 1, -53, -97, 13, -102, -9, 98, -36, 23, 93, -44, -11, 27, 116, 115, 107, 8, -114, 113, 116, 7)
        val plainTextSecond = byteArrayOf(2, -86, 3, -15, 91, -14, 88, 9, -68, -104, -71, 63, 0, -31, -11, 5, 0, 0, 0, 0, -127, 104, 110, -59, -98, -71, 94, -108, 72, -128, -69, 90, -50, -33, 92, -5, -76, 60, 54, -124, -1, -112, 12, -109, 123, -92, 65, -34, -22, 39, 48, -67)
        val plainText2 = byteArrayOf(2, -40, -89, -3, 10, 80, 100, -7, 28, 26, 4, -16, 0, -31, -11, 5, 0, 0, 0, 0, 86, 78, -32, 112, -124, -14, 105, -55, -113, -75, -26, -78, -92, -45, 92, 37, 9, 10, -39, -9, -66, -40, -7, 23, -10, 31, -73, 73, -18, -43, -128, 44)
        val plainTextTestnet = byteArrayOf(2, -55, -39, 61, 63, -23, 111, -78, 26, 110, 44, 48, 27, 88, -38, -63, 65, -32, 59, 102, 35, 115, 37, -55, -73, 70, -4, 66, 54, -53, -125, 19, 75, 120, -52, -4, 27, 9, 24, 2, -113, 111, 28, 65, -37, -72, 39, 125, -42, 30, -114, 126)
    }

    @Before
    fun initNativeLibrary() {
        try {
            ZecLibRustApi.init(ApplicationProvider.getApplicationContext())
        } catch (e: Exception) {
            println("ZecLibRustApi.init e=${e.message}")
        }
    }

    @Test
    fun encryptNp() {
        val res1 = ZecLibRustApi.encryptNp(key, note + ByteArray(512))
        println("res1 = $res1")
    }

    @Test
    fun testCmRseed() {
//        val cmuExpected = "40051aeb99e2b7cf32591ca710b2ba1b4e9413feb99d52b8c931184a4f094314"
        val cmuExpected = "101015eca2b76b0fb002d05eb1bd1bb8be61c26419dd5f4269bf51d399909ca4"
        val res1 = ZecLibRustApi.cmRseed(reverseByteArray(ivkSecond),  (plainTextSecond))
        println("res1 = ${Arrays.toString(res1)}")
        println("res1 hex = ${bytesToHex(res1)}")

        val cmuFromLibRevertedHex = bytesToHex(reverseByteArray(res1))
        println("res1 hex reverted = $cmuFromLibRevertedHex")

        assertEquals(cmuExpected, cmuFromLibRevertedHex)
    }

    @Test
    fun testComputeNf() {
        val nfExpected = "1a36d31edce5bdf026aa8d111ff2c394a789264ba64a0dd326b1b084cf2e9c01"

        val ak = "3995b253b7741573de048d032d10df145712b4ea61b7e14b45898c92110ba95e"
        val nk = "a3e49eb2c28afda36a9acb8d8abff3d1f78708b464c71b91893b4a008f56db5b"
        val position = 103677
        val resBytes = ZecLibRustApi.nullifier(
            reverseByteArray(ivkSecond),
            (plainTextSecond),
            reverseByteArray(hexToBytes(ak)),
            reverseByteArray(hexToBytes(nk)),
            position
        )
        println("res1 = ${Arrays.toString(resBytes)}")
        val nfFromLibRevertedHex = bytesToHex(resBytes)
        println("res1 hex = $nfFromLibRevertedHex")

        assertEquals(nfExpected, nfFromLibRevertedHex)
    }

    @Test
    fun testComputeNfSecond() {
        val ivkBytes = byteArrayOf(66, 84, 49, 126, 45, 121, -50, 7, -99, -68, -89, -120, 58, -115, -40, -32, -40, 41, -44, -23, 88, -57, 10, 14, 94, -74, 110, 53, -98, 100, 5, 3)
        val plainTextBytes = byteArrayOf(2, -86, 3, -15, 91, -14, 88, 9, -68, -104, -71, 63, 0, -31, -11, 5, 0, 0, 0, 0, -127, 104, 110, -59, -98, -71, 94, -108, 72, -128, -69, 90, -50, -33, 92, -5, -76, 60, 54, -124, -1, -112, 12, -109, 123, -92, 65, -34, -22, 39, 48, -67)
        val akBytes = byteArrayOf(94, -87, 11, 17, -110, -116, -119, 69, 75, -31, -73, 97, -22, -76, 18, 87, 20, -33, 16, 45, 3, -115, 4, -34, 115, 21, 116, -73, 83, -78, -107, 57)
        val nkBytes = byteArrayOf(91, -37, 86, -113, 0, 74, 59, -119, -111, 27, -57, 100, -76, 8, -121, -9, -47, -13, -65, -118, -115, -53, -102, 106, -93, -3, -118, -62, -78, -98, -28, -93)
        val position = 103677

        val resBytes = ZecLibRustApi.nullifier(
            (ivkBytes),
            (plainTextBytes),
            (akBytes),
            (nkBytes),
            position
        )
        println("res1 = ${Arrays.toString(resBytes)}")
        val nfFromLibRevertedHex = bytesToHex(resBytes)
        println("res1 hex = $nfFromLibRevertedHex")
    }


}