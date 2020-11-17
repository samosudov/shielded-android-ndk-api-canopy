package work.samosudov.rustlib

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import work.samosudov.rustlib.crypto.Utils.*
import java.util.*

class ZecLibRustApiTest {

    companion object {
        val note = byteArrayOf(1, 49, -56, 16, 72, -122, 103, 46, 68, 17, 99, 117, -96, 105, 117, 0, 0, 0, 0, 0, 76, -96, 22, 106, 90, -59, 124, 1, -55, 48, 96, 10, -60, 49, -63, 1, 15, -41, -72, -75, -104, -57, 42, 47, 3, 54, -24, -65, -62, -52, 77, 14)
        val key = byteArrayOf(69, 121, -20, 127, -124, -3, 114, -88, 7, -102, 47, 22, -12, -31, -92, -93, -41, 62, 32, -6, -80, -24, 115, 22, 115, -83, -91, -43, 98, 103, -54, -15)
        val ivk = hexToBytes("00c11ba0a37371bd41ba456fb95d36c09b55d2ac9fa9e62bc71d1b08d3bc78b4")
        val plainText = byteArrayOf(2, 107, 32, 71, -62, -6, 78, -7, -113, -2, -91, 59, -110, -53, 62, 53, -47, -37, 86, 61, -86, 116, -58, -116, -110, 68, -91, 5, -64, 90, 106, 1, -53, -97, 13, -102, -9, 98, -36, 23, 93, -44, -11, 27, 116, 115, 107, 8, -114, 113, 116, 7)
        val plainText2 = byteArrayOf(2, -40, -89, -3, 10, 80, 100, -7, 28, 26, 4, -16, 0, -31, -11, 5, 0, 0, 0, 0, 86, 78, -32, 112, -124, -14, 105, -55, -113, -75, -26, -78, -92, -45, 92, 37, 9, 10, -39, -9, -66, -40, -7, 23, -10, 31, -73, 73, -18, -43, -128, 44)
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
        val cmuExpected = "40051aeb99e2b7cf32591ca710b2ba1b4e9413feb99d52b8c931184a4f094314"
        val res1 = ZecLibRustApi.cmRseed(reverseByteArray(ivk),  (plainText2))
        println("res1 = ${Arrays.toString(res1)}")
        println("res1 hex = ${bytesToHex(res1)}")

        val cmuFromLibRevertedHex = bytesToHex(reverseByteArray(res1))
        println("res1 hex reverted = $cmuFromLibRevertedHex")

        assertEquals(cmuExpected, cmuFromLibRevertedHex)
    }

}