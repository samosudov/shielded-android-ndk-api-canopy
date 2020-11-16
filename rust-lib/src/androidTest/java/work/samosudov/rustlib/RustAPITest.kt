package work.samosudov.rustlib

import androidx.test.core.app.ApplicationProvider
import org.junit.Before
import org.junit.Test

class RustAPITest {

    companion object {
        val note = byteArrayOf(1, 49, -56, 16, 72, -122, 103, 46, 68, 17, 99, 117, -96, 105, 117, 0, 0, 0, 0, 0, 76, -96, 22, 106, 90, -59, 124, 1, -55, 48, 96, 10, -60, 49, -63, 1, 15, -41, -72, -75, -104, -57, 42, 47, 3, 54, -24, -65, -62, -52, 77, 14)
        val key = byteArrayOf(69, 121, -20, 127, -124, -3, 114, -88, 7, -102, 47, 22, -12, -31, -92, -93, -41, 62, 32, -6, -80, -24, 115, 22, 115, -83, -91, -43, 98, 103, -54, -15)
    }

    @Before
    fun initNativeLibrary() {
        try {
            RustAPI.init(ApplicationProvider.getApplicationContext())
        } catch (e: Exception) {
            println("RustAPI.init e=${e.message}")
        }
    }

    @Test
    fun encryptNp() {
        val res1 = RustAPI.encryptNp(key, note + ByteArray(512))
        println("res1 = $res1")
    }

}