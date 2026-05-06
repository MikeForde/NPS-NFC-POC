package uk.meds.ipsnfc

import android.nfc.Tag
//import android.nfc.tech.IsoDep
import android.util.Log
import nfcjlib.core.DESFireAdapter
import nfcjlib.core.DESFireEV1
import nfcjlib.core.KeyType
//import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile;

// Our test application + files on the card
// Use a fresh AID so we don't collide with any previous experiments
private val IPS_AID: ByteArray = byteArrayOf(0x44, 0x55, 0x66)

private const val FILE_HIST: Byte = 0x01
private const val FILE_RW: Byte = 0x02

// Keep this modest for now
private const val TEST_FILE_SIZE_BYTES = 512

// Default keys (same as Java sample)
private val DEFAULT_DES_KEY  = ByteArray(8) { 0x00 }  // 00..00

// Application key layout: copy the Java logic
private const val APPLICATION_MASTER_KEY_SETTINGS: Byte = 0x0F
private const val APPLICATION_KEY_COUNT: Byte = 5

private const val KEYNO_MASTER: Byte = 0x00
private const val KEYNO_RW: Byte     = 0x01
private const val KEYNO_CAR: Byte    = 0x02
private const val KEYNO_R: Byte      = 0x03
private const val KEYNO_W: Byte      = 0x04

data class TestPayload(
    val historic: ByteArray,
    val rw: ByteArray
)

/**
 * Thin Kotlin wrapper around the DESFire EV1 Java library.
 *
 * Responsibilities:
 *  - connect to a DESFire EVx card using IsoDep
 *  - wire IsoDep -> DefaultIsoDepWrapper -> DefaultIsoDepAdapter -> DESFireAdapter -> DESFireEV1
 *  - expose simple helpers for reading/writing a standard data file
 */
class DesfireHelper private constructor(
    private val transport: ApduTransport,
    val desfire: DESFireEV1
) {
    /**
     * Ensure our IPS application + 2 standard files exist, but
     * do NOT format the PICC. This is safe to call repeatedly.
     */
    @Synchronized
    fun ensureIpsAppAndFilesNonDestructive() {
        try {
            // 1. Go to PICC (master application)
            desfire.selectApplication(byteArrayOf(0x00, 0x00, 0x00))

            // 2. Try to auth to PICC master (default 0x00..00); ignore failure
            runCatching {
                desfire.authenticate(DEFAULT_DES_KEY, 0x00.toByte(), KeyType.DES)
            }

            // 3. Try to create our IPS application; if it already exists,
            // most libs just return false – we ignore that.
            runCatching {
                desfire.createApplication(
                    IPS_AID,
                    0x0F.toByte(),   // permissive key settings
                    KeyType.DES,
                    3.toByte()       // 3 keys
                )
            }

            // 4. Select our IPS app (must succeed if it already exists or was created)
            if (!desfire.selectApplication(IPS_AID)) {
                throw RuntimeException("Failed to select IPS AID (non-destructive)")
            }

            // 5. Authenticate to app master key (key 0, default 0x00..00)
            if (!desfire.authenticate(DEFAULT_DES_KEY, 0x00.toByte(), KeyType.DES)) {
                throw RuntimeException("App master key auth failed (non-destructive)")
            }

            // 6. Try to create our 2 standard files; if they already exist,
            // createStdDataFile() will fail/return false – we just log and continue.
            val builder = PayloadBuilder()

            runCatching {
                val histPayload = builder.createStandardFile(
                    FILE_HIST.toInt(),
                    PayloadBuilder.CommunicationSetting.Plain,
                    keyRW = 0xE,
                    keyCar = 0xE,
                    keyR = 0xE,   // free read
                    keyW = 0xE,   // free write
                    fileSize = TEST_FILE_SIZE_BYTES
                )
                if (histPayload != null) {
                    desfire.createStdDataFile(histPayload)
                }
            }.onFailure {
                Log.w(TAG, "createStdDataFile(HIST) failed or already exists", it)
            }

            runCatching {
                val rwPayload = builder.createStandardFile(
                    FILE_RW.toInt(),
                    PayloadBuilder.CommunicationSetting.Plain,
                    keyRW = 0xE,
                    keyCar = 0xE,
                    keyR = 0xE,
                    keyW = 0xE,
                    fileSize = TEST_FILE_SIZE_BYTES
                )
                if (rwPayload != null) {
                    desfire.createStdDataFile(rwPayload)
                }
            }.onFailure {
                Log.w(TAG, "createStdDataFile(RW) failed or already exists", it)
            }

        } catch (e: Exception) {
            Log.e(TAG, "ensureIpsAppAndFilesNonDestructive failed", e)
            throw e
        }
    }


    /**
     * Ensure our test application and the two standard data files exist.
     * - Does NOT format or otherwise wipe the card.
     * - Only creates the AID / files if they don't exist.
     *
     * This is intended to be called from WRITE paths only.
     */
    @Synchronized
    private fun ensureTestAppAndFiles(requiredHistBytes: Int, requiredRwBytes: Int) {
        try {
            // Decide final target sizes (add headroom + align)
            val targetHist = chooseFileSize(requiredHistBytes)
            val targetRw   = chooseFileSize(requiredRwBytes)

            // 1) Go to PICC
            desfire.selectApplication(byteArrayOf(0x00, 0x00, 0x00))

            // 2) Ensure our app exists
            val apps = desfire.applicationsIds
            val appExists = apps?.any { it.id contentEquals IPS_AID } == true

            if (!appExists) {
                runCatching { desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES) }
                val created = desfire.createApplication(
                    IPS_AID,
                    APPLICATION_MASTER_KEY_SETTINGS,
                    KeyType.DES,
                    APPLICATION_KEY_COUNT
                )
                Log.d(TAG, "createApplication(IPS_AID) -> $created")
                if (!created) throw RuntimeException("Failed to create IPS app")
            }

            // 3) Select our app
            if (!desfire.selectApplication(IPS_AID)) {
                throw RuntimeException("Failed to select IPS AID")
            }

            // 4) Inspect existing files (if present) and their sizes
            val fileIds = runCatching { desfire.fileIds }.getOrElse {
                Log.e(TAG, "getFileIds failed", it)
                ByteArray(0)
            }

            val haveHist = fileIds.any { it == FILE_HIST }
            val haveRw   = fileIds.any { it == FILE_RW }

            val histSizeNow = if (haveHist) (desfire.getFileSettings(FILE_HIST.toInt()) as? StandardDesfireFile)?.fileSize else null
            val rwSizeNow   = if (haveRw)   (desfire.getFileSettings(FILE_RW.toInt())   as? StandardDesfireFile)?.fileSize else null

            val needResizeHist = haveHist && histSizeNow != null && histSizeNow < targetHist
            val needResizeRw   = haveRw   && rwSizeNow   != null && rwSizeNow   < targetRw

            // 5) If we need to create or resize, authenticate with app master
            if (!haveHist || !haveRw || needResizeHist || needResizeRw) {
                val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
                if (!appAuthOk) throw RuntimeException("App master key auth failed")
            }

            // 6) Delete + recreate if too small
            if (needResizeHist) {
                Log.w(TAG, "HIST file too small ($histSizeNow). Recreating to $targetHist bytes.")
                deleteFileSafe(FILE_HIST)
            }
            if (needResizeRw) {
                Log.w(TAG, "RW file too small ($rwSizeNow). Recreating to $targetRw bytes.")
                deleteFileSafe(FILE_RW)
            }

            val pb = PayloadBuilder()

            if (!haveHist || needResizeHist) {
                val histPayload = pb.createStandardFile(
                    FILE_HIST.toInt(),
                    PayloadBuilder.CommunicationSetting.Plain,
                    KEYNO_RW.toInt(),
                    KEYNO_CAR.toInt(),
                    KEYNO_R.toInt(),
                    KEYNO_W.toInt(),
                    targetHist
                ) ?: throw RuntimeException("createStandardFile(HIST) returned null")

                val created = desfire.createStdDataFile(histPayload)
                Log.d(TAG, "createStdDataFile(HIST) -> $created (size=$targetHist)")
                if (!created) throw RuntimeException("Failed to create HIST file (code=${desfire.code.toString(16)} ${desfire.codeDesc})")
            }

            if (!haveRw || needResizeRw) {
                val rwPayload = pb.createStandardFile(
                    FILE_RW.toInt(),
                    PayloadBuilder.CommunicationSetting.Plain,
                    KEYNO_RW.toInt(),
                    KEYNO_CAR.toInt(),
                    KEYNO_R.toInt(),
                    KEYNO_W.toInt(),
                    targetRw
                ) ?: throw RuntimeException("createStandardFile(RW) returned null")

                val created = desfire.createStdDataFile(rwPayload)
                Log.d(TAG, "createStdDataFile(RW) -> $created (size=$targetRw)")
                if (!created) throw RuntimeException("Failed to create RW file (code=${desfire.code.toString(16)} ${desfire.codeDesc})")
            }

        } catch (e: Exception) {
            Log.e(TAG, "ensureTestAppAndFiles failed", e)
            throw e
        }
    }

    private fun deleteFileSafe(fileNo: Byte) {
        // nfcjlib has deleteFile() on DESFireEV1 in most builds; if yours differs, shout and we’ll adjust.
        val ok = runCatching { desfire.deleteFile(fileNo) }.getOrElse { false }
        Log.d(TAG, "deleteFile($fileNo) -> $ok (code=${desfire.code.toString(16)} ${desfire.codeDesc})")
        if (!ok) throw RuntimeException("Failed to delete file $fileNo (code=${desfire.code.toString(16)} ${desfire.codeDesc})")
    }

    /** Choose a file size that fits payload + headroom, aligned. */
    private fun chooseFileSize(payloadBytes: Int): Int {
        val headroom = 64                 // small growth margin
        val minSize  = 256                // sensible minimum
        val align    = 32                 // align to 32 bytes

        val wanted = payloadBytes + headroom
        val base = maxOf(minSize, wanted)
        return ((base + (align - 1)) / align) * align
    }


    companion object {
        private const val TAG = "DesfireHelper"

        fun connect(tag: Tag, debug: Boolean = false): DesfireHelper? {
            val transport = AndroidIsoDepTransport.connect(tag, timeoutMs = 5000)

            if (transport == null) {
                Log.w(TAG, "Tag does not support IsoDep – not a DESFire EVx card")
                return null
            }

            return try {
                connect(transport, debug)
            } catch (e: Exception) {
                Log.e(TAG, "Error connecting to DESFire tag", e)
                transport.close()
                null
            }
        }

        fun connect(
            transport: ApduTransport,
            debug: Boolean = false
        ): DesfireHelper {
            val wrapper = ApduTransportIsoDepWrapper(transport)
            val adapter = DESFireAdapter(wrapper, /* print */ debug)

            val desfire = DESFireEV1().apply {
                setAdapter(adapter)
            }

            return DesfireHelper(transport, desfire)
        }
    }



    fun close() {
        try {
            transport.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing ${transport.name}", e)
        }
    }

    // -------------------------
    // Basic info helpers
    // -------------------------

    fun formatPicc(): Boolean {
        return try {
            // 1) Select master application 000000
            if (!desfire.selectApplication(byteArrayOf(0x00, 0x00, 0x00))) {
                Log.e(TAG, "formatPicc: failed to select master application")
                return false
            }

            // 2) Authenticate with PICC master key (DES 00..00, key #0)
            val authOk = desfire.authenticate(DEFAULT_DES_KEY, 0x00.toByte(), KeyType.DES)
            if (!authOk) {
                Log.e(TAG, "formatPicc: PICC master auth failed")
                return false
            }

            // 3) Format the PICC (removes ALL apps & files)
            val ok = desfire.formatPICC()
            Log.d(
                TAG,
                "formatPICC -> $ok code=${desfire.code.toString(16)} desc=${desfire.codeDesc}"
            )
            ok
        } catch (e: Exception) {
            Log.e(TAG, "formatPicc failed", e)
            false
        }
    }


    fun deleteTestApplication(): Boolean {
        return try {
            // 1) Select PICC / master application (00 00 00)
            if (!desfire.selectApplication(byteArrayOf(0x00, 0x00, 0x00))) {
                Log.e(TAG, "deleteTestApplication: failed to select master application")
                return false
            }

            // 2) Authenticate with PICC master key (default DES 00..00, key #0)
            val authOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!authOk) {
                Log.e(TAG, "deleteTestApplication: PICC master auth failed")
                return false
            }

            // 3) Delete our IPS application (AID is already LSB in IPS_AID)
            val ok = desfire.deleteApplication(IPS_AID)
            Log.d(
                TAG,
                "deleteApplication(IPS_AID = 665544) -> $ok (code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})"
            )
            ok
        } catch (e: Exception) {
            Log.e(TAG, "deleteTestApplication failed", e)
            false
        }
    }

    /**
     * Get a human-readable version string, or null on error.
     * Good sanity check that the DESFire stack is working.
     */
    fun getVersionSummary(): String? {
        return try {
            val version = desfire.version  // DESFireEV1.getVersion()
            if (version == null) {
                null
            } else {
                buildString {
                    append("HW: ${version.hardwareType} v${version.hardwareVersionMajor}.${version.hardwareVersionMinor}\n")
                    append("SW: ${version.softwareType} v${version.softwareVersionMajor}.${version.softwareVersionMinor}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "getVersionSummary failed", e)
            null
        }
    }

    /**
     * Get card UID (requires authentication on EV1+, but for many cards this
     * works with default keys; if not, we’ll wire in auth later).
     */
    fun getUidHex(): String? = try {
        val uid = desfire.cardUID  // DESFireEV1.getCardUID()
        uid?.joinToString("") { "%02X".format(it) }
    } catch (e: Exception) {
        Log.e(TAG, "getUidHex failed", e)
        null
    }

    /**
     * Non-destructive writer for our IPS payload:
     *  - DOES NOT format the PICC
     *  - Ensures app + files exist (idempotent)
     *  - Writes full contents of historic + RW (capped to file size)
     */
    fun writeIpsPayloadNonDestructive(historic: ByteArray, rw: ByteArray): Boolean {
        return try {
            ensureIpsAppAndFilesNonDestructive()

            val okHist = writeOneStandardFile(FILE_HIST, historic)
            val okRw   = writeOneStandardFile(FILE_RW, rw)

            Log.d(TAG, "writeIpsPayloadNonDestructive hist=$okHist rw=$okRw")
            okHist && okRw
        } catch (e: Exception) {
            Log.e(TAG, "writeIpsPayloadNonDestructive failed", e)
            false
        }
    }


    /**
     * Write test payload into FILE_HIST and FILE_RW in our test application.
     */
    fun writeTestPayload(historic: ByteArray, rw: ByteArray): Boolean {
        return try {
            ensureTestAppAndFiles(
                requiredHistBytes = historic.size,
                requiredRwBytes   = rw.size
            )

            // 1) Select our app
            if (!desfire.selectApplication(IPS_AID)) {
                Log.e(TAG, "writeTestPayload: failed to select app")
                return false
            }

            // 2) Authenticate with RW key (like pressing authD1D in the Java app)
            val authOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_RW, KeyType.DES)
            if (!authOk) {
                Log.e(TAG, "writeTestPayload: RW key auth failed")
                return false
            }

            val okHist = writeOneStandardFile(FILE_HIST, historic)
            val okRw   = writeOneStandardFile(FILE_RW, rw)

            okHist && okRw
        } catch (e: Exception) {
            Log.e(TAG, "writeTestPayload failed", e)
            false
        }
    }

    private fun writeOneStandardFile(fileNo: Byte, data: ByteArray): Boolean {
        val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile
            ?: throw RuntimeException("File $fileNo is not Standard / not found")

        val fileSize = fs.fileSize

        if (data.size > fileSize) {
            Log.e(TAG, "writeOneStandardFile($fileNo): payload ${data.size} > fileSize $fileSize (REFUSING to truncate)")
            return false
        }

        val fullData = ByteArray(fileSize)
        System.arraycopy(data, 0, fullData, 0, data.size)

        val pb = PayloadBuilder()
        val payload = pb.writeToStandardFile(fileNo.toInt(), fullData)
            ?: throw RuntimeException("writeToStandardFile($fileNo) returned null")

        Log.d(TAG, "writeOneStandardFile($fileNo) size=$fileSize, payloadLen=${payload.size}")

        val ok = desfire.writeData(payload)
        Log.d(TAG, "writeOneStandardFile($fileNo) -> $ok (code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})")
        return ok
    }


    /**
     * Read test payload from FILE_HIST and FILE_RW in our test application.
     */
    fun readTestPayload(): TestPayload? {
        return try {
            // 1) Select our app
            if (!desfire.selectApplication(IPS_AID)) {
                Log.w(TAG, "readTestPayload: app not present / not selectable")
                return null
            }

            // 2) Authenticate with RW key (good enough for read)
            val authOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_RW, KeyType.DES)
            if (!authOk) {
                Log.e(TAG, "readTestPayload: RW key auth failed")
                return null
            }

            val histBytes = readOneStandardFile(FILE_HIST) ?: return null
            val rwBytes   = readOneStandardFile(FILE_RW)   ?: return null

            TestPayload(historic = histBytes, rw = rwBytes)
        } catch (e: Exception) {
            Log.e(TAG, "readTestPayload failed", e)
            null
        }
    }

    private fun readOneStandardFile(fileNo: Byte): ByteArray? {
        val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile
            ?: run {
                Log.e(TAG, "readOneStandardFile($fileNo): not a Standard file")
                return null
            }

        val size = fs.fileSize
        Log.d(TAG, "readOneStandardFile($fileNo): size=$size")

        val data = desfire.readData(fileNo, 0, size)
        if (data == null) {
            Log.e(TAG, "readOneStandardFile($fileNo): readData returned null (code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})")
        }

        return data
    }

}