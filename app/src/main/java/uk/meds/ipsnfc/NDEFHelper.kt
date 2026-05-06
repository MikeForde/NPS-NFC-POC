package uk.meds.ipsnfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile
import nfcjlib.core.DESFireAdapter
import nfcjlib.core.DESFireEV1
import nfcjlib.core.KeyType
import kotlin.math.max
import kotlin.math.min
import android.nfc.tech.NdefFormatable
import android.nfc.NdefMessage
import android.nfc.NdefRecord


/**
 * Standalone helper for setting up a "dual section" layout on a DESFire card:
 *
 *  - Read-only NDEF lives in the *standard* Type 4 NDEF application (e.g. AID 000001),
 *    and is written via android.nfc.tech.Ndef – any NFC reader can see this.
 *
 *  - This helper manages a *separate* DESFire application (AID 0x665544) which holds
 *    ONE read/write "extra" blob in a standard data file.
 *
 * Layout inside AID 0x665544:
 *  - Application AID: 0x44 0x55 0x66 (IPS_AID)
 *  - File 0x01: RW "extra" blob, stored as a single NDEF MIME record
 */

class NDEFHelper private constructor(
    private val isoDep: IsoDep,
    private val desfire: DESFireEV1
) {

    fun close() {
        try {
            if (isoDep.isConnected) {
                isoDep.close()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error closing IsoDep", e)
        }
    }

    fun readExtraPlain(): ByteArray? {
        return try {
            // Select our IPS app (0x665544)
            if (!desfire.selectApplication(IPS_AID)) {
                Log.w(TAG, "readExtraPlain: IPS app not present / not selectable")
                null
            } else {
                // Get file settings to determine size
                val fs = desfire.getFileSettings(FILE_EXTRA.toInt()) as? StandardDesfireFile
                    ?: run {
                        Log.e(TAG, "readExtraPlain: file $FILE_EXTRA not found or not Standard file")
                        return null
                    }

                val size = fs.fileSize
                Log.d(TAG, "readExtraPlain: file size=$size")

                val data = desfire.readData(FILE_EXTRA, 0, size)
                if (data == null) {
                    Log.e(
                        TAG,
                        "readExtraPlain: readData returned null (code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})"
                    )
                }
                data
            }
        } catch (e: Exception) {
            Log.e(TAG, "readExtraPlain failed", e)
            null
        }
    }


    /**
     * High-level entry:
     *
     *  - Ensures the IPS AID (0x665544) and two standard files exist (non-destructive).
     *  - Writes:
     *      roMimeType + roPayload -> FILE_HIST (0x01) as a single NDEF MIME record
     *      rwMimeType + rwPayload -> FILE_RW   (0x02) as a single NDEF MIME record
     *
     * Does *not* touch any other apps (e.g. existing Type 4 NDEF app 000001).
     */
    /**
     * High-level entry for the "extra" (RW) section.
     *
     *  - The read-only NDEF blob is written elsewhere via android.nfc.tech.Ndef
     *    into the standard Type 4 NDEF app (e.g. 000001).
     *
     *  - This function ONLY ensures that our private IPS app (0x665544) exists
     *    and that it contains one RW standard data file (FILE_EXTRA = 0x01),
     *    and then writes a single NDEF MIME record into that file.
     */
    fun writeDualSectionNdef(
        roMimeType: String,
        roPayload: ByteArray,
        rwMimeType: String,
        rwPayload: ByteArray
    ): Boolean {
        return try {
            // 1) RO NPS into Type-4 NDEF file in 000001
            val npsOk = writeType4NdefRo(roMimeType, roPayload)
            if (!npsOk) {
                Log.e(TAG, "writeDualSectionNdef: failed to write RO NPS into Type-4 NDEF file")
                return false
            }

            // 2) Extra into private app 665544 (as NDEF MIME record)
            val extraNdef = buildMimeNdefRecord(rwMimeType, rwPayload)

            // We store the record bytes directly in the file
            val desiredExtraFileSize = chooseExtraFileSize(extraNdef.size)

            if (!ensureIpsAppAndExtraFile(desiredExtraFileSize)) {
                Log.e(TAG, "writeDualSectionNdef: ensureIpsAppAndExtraFile failed")
                return false
            }

            val okExtra = writeStandardFileInternal(FILE_EXTRA, extraNdef)
            Log.d(TAG, "writeDualSectionNdef: okExtra=$okExtra")

            npsOk && okExtra
        } catch (e: Exception) {
            Log.e(TAG, "writeDualSectionNdef failed", e)
            false
        }
    }

    private fun chooseExtraFileSize(requiredBytes: Int): Int {
        val headroom = 64
        val minSize  = MIN_EXTRA_FILE_SIZE
        val align    = 32
        val base = max(minSize, requiredBytes + headroom)
        return ((base + (align - 1)) / align) * align
    }

    /**
     * Ensure our IPS application and the two standard data files exist.
     *
     *  - NO formatPICC
     *  - Creates the AID 0x665544 only if missing
     *  - Creates/extends FILE_HIST (RO) and FILE_RW (RW) if missing
     *
     * roSize / rwSize are the desired logical payload sizes (we may round up).
     */
    @Synchronized
    private fun ensureIpsAppAndExtraFile(extraSize: Int): Boolean {
        try {
            desfire.selectApplication(MASTER_AID)

            val apps = runCatching { desfire.applicationsIds }.getOrNull()
            val appExists = apps?.any { it.id contentEquals IPS_AID } == true

            if (!appExists) {
                runCatching { desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES) }

                val created = desfire.createApplication(
                    IPS_AID,
                    APPLICATION_MASTER_KEY_SETTINGS,
                    KeyType.DES,
                    APPLICATION_KEY_COUNT
                )
                Log.d(TAG, "NDEFHelper: createApplication(IPS_AID) -> $created code=${desfire.code.toString(16)} desc=${desfire.codeDesc}")

                if (!created && desfire.code != 0xDE) {
                    Log.e(TAG, "NDEFHelper: failed to create IPS app code=${desfire.code.toString(16)} desc=${desfire.codeDesc}")
                    return false
                }
            }

            if (!desfire.selectApplication(IPS_AID)) {
                Log.e(TAG, "NDEFHelper: failed to select IPS AID")
                return false
            }

            val fileIds = runCatching { desfire.fileIds }.getOrElse {
                Log.e(TAG, "NDEFHelper: getFileIds failed", it)
                ByteArray(0)
            }

            val haveExtra = fileIds.any { it == FILE_EXTRA }

            // We need app master auth to create OR delete/recreate
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "NDEFHelper: app master key auth failed")
                return false
            }

            val desired = max(extraSize, MIN_EXTRA_FILE_SIZE)

            if (haveExtra) {
                val fs = desfire.getFileSettings(FILE_EXTRA.toInt()) as? StandardDesfireFile
                val current = fs?.fileSize ?: 0

                if (current >= desired) {
                    Log.d(TAG, "NDEFHelper: FILE_EXTRA exists size=$current (ok)")
                    return true
                }

                Log.w(TAG, "NDEFHelper: FILE_EXTRA too small ($current). Recreating to $desired.")

                val deleted = runCatching { desfire.deleteFile(FILE_EXTRA) }.getOrElse { false }
                Log.d(TAG, "NDEFHelper: deleteFile(FILE_EXTRA) -> $deleted code=${desfire.code.toString(16)} desc=${desfire.codeDesc}")
                if (!deleted) return false
            }

            // Create (or recreate) EXTRA as RW (free read/write)
            val pb = PayloadBuilder()
            val extraPayload = pb.createStandardFile(
                FILE_EXTRA.toInt(),
                PayloadBuilder.CommunicationSetting.Plain,
                keyRW = KEYNO_RW.toInt(),
                keyCar = KEYNO_CAR.toInt(),
                keyR = 0xE,  // free read
                keyW = 0xE,  // free write
                fileSize = desired
            ) ?: throw RuntimeException("NDEFHelper: createStandardFile(EXTRA) returned null")

            val createdExtra = desfire.createStdDataFile(extraPayload)
            Log.d(TAG, "NDEFHelper: createStdDataFile(EXTRA) -> $createdExtra code=${desfire.code.toString(16)} desc=${desfire.codeDesc}")

            if (!createdExtra) {
                Log.e(TAG, "NDEFHelper: failed to create EXTRA file code=${desfire.code.toString(16)} desc=${desfire.codeDesc}")
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "NDEFHelper: ensureIpsAppAndExtraFile failed", e)
            return false
        }
        return true
    }


    /**
     * Internal: write a whole Standard Data File from offset 0.
     *
     *  - Selects IPS_AID
     *  - Authenticates with master key (00..00, key #0)
     *  - Looks up file size, pads/truncates the payload to fit
     *  - Uses PayloadBuilder.writeToStandardFile + desfire.writeData
     */
    private fun writeStandardFileInternal(fileNo: Byte, data: ByteArray): Boolean {
        return try {
            if (!desfire.selectApplication(IPS_AID)) {
                Log.e(TAG, "writeStandardFileInternal($fileNo): failed to select IPS app")
                return false
            }

            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "writeStandardFileInternal($fileNo): app master key auth failed")
                return false
            }

            val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile
                ?: run {
                    Log.e(TAG, "writeStandardFileInternal($fileNo): not a Standard file / not found")
                    return false
                }

            val fileSize = fs.fileSize
            if (data.size > fileSize) {
                Log.e(TAG, "writeStandardFileInternal($fileNo): payload ${data.size} > fileSize $fileSize (REFUSING to truncate)")
                return false
            }

            val fullData = ByteArray(fileSize)
            System.arraycopy(data, 0, fullData, 0, data.size)

            val pb = PayloadBuilder()
            val payloadApdu = pb.writeToStandardFile(fileNo.toInt(), fullData)
                ?: throw RuntimeException("writeToStandardFile($fileNo) returned null")

            Log.d(TAG, "writeStandardFileInternal($fileNo): fileSize=$fileSize, payloadLen=${payloadApdu.size}")

            val ok = desfire.writeData(payloadApdu)
            Log.d(TAG, "writeStandardFileInternal($fileNo) -> $ok code=${desfire.code.toString(16)} desc=${desfire.codeDesc}")
            ok
        } catch (e: Exception) {
            Log.e(TAG, "writeStandardFileInternal($fileNo) failed", e)
            false
        }
    }


    /**
     * Write a single-message NDEF MIME record into the standard Type-4
     * NDEF file in app 000001 (FILE_NDEF = 0x02).
     *
     * Layout in the file: [NLEN (2 bytes, BE)] + [NDEF message] + padding zeros.
     */
    private fun writeType4NdefRo(
        mimeType: String,
        payload: ByteArray
    ): Boolean {
        return try {
            // 1) Select NFC Forum NDEF app (000001)
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "writeType4NdefRo: failed to select NDEF app (000001)")
                return false
            }

            // 2) Authenticate with app master key (00..00, key 0)
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "writeType4NdefRo: app master key auth failed")
                return false
            }

            // 3) Get file settings to know capacity of FILE_NDEF
            val fs = desfire.getFileSettings(FILE_NDEF.toInt()) as? StandardDesfireFile
                ?: run {
                    Log.e(TAG, "writeType4NdefRo: FILE_NDEF not found or not Standard file")
                    return false
                }

            val capacity = fs.fileSize
            val ndefRecord = buildMimeNdefRecord(mimeType, payload)
            val msgLen = ndefRecord.size

            if (msgLen + 2 > capacity) {
                Log.e(
                    TAG,
                    "writeType4NdefRo: NDEF message too large ($msgLen bytes) for capacity $capacity"
                )
                return false
            }

            val fileBytes = ByteArray(capacity) { 0 }
            // NLEN (big-endian)
            fileBytes[0] = ((msgLen shr 8) and 0xFF).toByte()
            fileBytes[1] = (msgLen and 0xFF).toByte()
            System.arraycopy(ndefRecord, 0, fileBytes, 2, msgLen)

            // 4) Write into file 0x02 in current app
            val ok = writeStandardFileInCurrentApp(FILE_NDEF, fileBytes)
            Log.d(TAG, "writeType4NdefRo: writeStandardFileInCurrentApp -> $ok")
            ok
        } catch (e: Exception) {
            Log.e(TAG, "writeType4NdefRo failed", e)
            false
        }
    }


    /**
     * Write a whole Standard Data File in the *currently selected application*.
     *
     * - Does NOT change the selected app (caller must have called selectApplication(..)).
     * - Authenticates with the app master key (00..00, key #0).
     * - Looks up file size, pads/truncates payload, then writeData().
     */
    private fun writeStandardFileInCurrentApp(fileNo: Byte, data: ByteArray): Boolean {
        return try {
            // 1) Authenticate with app master key (key 0, 00..00)
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "writeStandardFileInCurrentApp($fileNo): app master auth failed")
                return false
            }

            // 2) Get file settings for this file number
            val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile
                ?: run {
                    Log.e(TAG, "writeStandardFileInCurrentApp($fileNo): not a Standard file / not found")
                    return false
                }

            val fileSize = fs.fileSize
            val fullData = ByteArray(fileSize)
            val len = min(fileSize, data.size)
            System.arraycopy(data, 0, fullData, 0, len)

            val pb = PayloadBuilder()
            val payload = pb.writeToStandardFile(fileNo.toInt(), fullData)
                ?: throw RuntimeException("writeToStandardFile($fileNo) returned null")

            Log.d(
                TAG,
                "writeStandardFileInCurrentApp($fileNo): fileSize=$fileSize, payloadLen=${payload.size}"
            )

            val ok = desfire.writeData(payload)
            Log.d(
                TAG,
                "writeStandardFileInCurrentApp($fileNo) -> $ok " +
                        "code=${desfire.code.toString(16)}, desc=${desfire.codeDesc}"
            )
            ok
        } catch (e: Exception) {
            Log.e(TAG, "writeStandardFileInCurrentApp($fileNo) failed", e)
            false
        }
    }


    /**
     * Internal: full PICC format (destructive).
     *
     *  - Selects PICC master (000000)
     *  - Authenticates with default master key (DES, 00..00, key #0)
     *  - Calls formatPICC() to wipe all apps & files
     */
    private fun formatPiccInternal(): Boolean {
        return try {
            // 1) Select master application 000000
            if (!desfire.selectApplication(MASTER_AID)) {
                Log.e(TAG, "formatPiccInternal: failed to select master application")
                false
            } else {
                // 2) Authenticate with PICC master key (DES 00..00, key #0)
                val authOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
                if (!authOk) {
                    Log.e(TAG, "formatPiccInternal: PICC master auth failed")
                    false
                } else {
                    // 3) Format the PICC (removes ALL apps & files)
                    val ok = desfire.formatPICC()
                    Log.d(
                        TAG,
                        "formatPiccInternal: formatPICC -> $ok " +
                                "code=${desfire.code.toString(16)} desc=${desfire.codeDesc}"
                    )
                    ok
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "formatPiccInternal failed", e)
            false
        }
    }

    /**
     * Low-level Type-4 formatting:
     *
     * 1) formatPICC()  -> erase all apps/files
     * 2) Create NFC Forum NDEF application:
     *      - DESFire AID = 0x000001 (NDEF_APP_AID)
     *      - ISO DF name = D2760000850101 (NDEF Tag application per NFC Forum)
     * 3) Inside that app, create:
     *      - CC file   (fileNo=1, ISO FID E103, size 32 bytes)
     *      - NDEF file (fileNo=2, ISO FID E104, size = ndefCapacityBytes)
     * 4) Write CC contents and seed NDEF content.
     */
    private fun lowLevelFormatPiccForDualNdef(
        seedMimeType: String,
        seedPayload: ByteArray,
        ndefCapacityBytes: Int
    ): Boolean {
        return try {
            // 1) Format the PICC via the usual API
            if (!formatPiccInternal()) {
                Log.e(TAG, "lowLevelFormatPiccForDualNdef: formatPiccInternal() failed")
                return false
            }

            // 2) Create NFC Forum Type 4 NDEF application using DESFire native command 0xCA
            // Body from AN11004 example:
            //   AID (little endian): 0x01 0x00 0x00
            //   Key settings: 0x0F  (permissive)
            //   App settings: 0x21  (ISO file support etc.)
            //   Number of keys + key type: 0x05 0x01
            //   ISO DF name (NDEF Tag app): D2 76 00 00 85 01 01
            val createNdefAppBody = byteArrayOf(
                0x01, 0x00, 0x00,       // AID = 000001 (little endian)
                0x0F,                   // key settings
                0x21,                   // app settings
                0x05, 0x01,             // 5 keys, key type DES
                0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01 // ISO DF name
            )
            val respCreateApp = sendNative(0xCA.toByte(), createNdefAppBody)
            val swCreateApp = respCreateApp.last().toInt() and 0xFF
            if (swCreateApp != 0x00 && swCreateApp != 0xDE) { // 0xDE = DUPLICATE_ERROR
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForDualNdef: create NDEF app failed, status=0x${swCreateApp.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForDualNdef: create NDEF app ok (or duplicate), status=0x${swCreateApp.toString(16)}"
                )
            }

            // 3) Select that NDEF app using the higher-level API
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "lowLevelFormatPiccForDualNdef: failed to select NDEF app (000001)")
                return false
            }

            // Authenticate with app master key (00..00, key 0)
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "lowLevelFormatPiccForDualNdef: app master auth failed")
                return false
            }

            // 4) Create CC file (fileNo=1, ISO FID E103, 32 bytes)
            // Native "Create Std Data File with ISO FID" command 0xCD
            // Body:
            //   fileNo:       0x01
            //   ISO FID:      0x03 0xE1   (E103)
            //   comm settings 0x00        (plain)
            //   access rights 0xEE 0xEE   (free R/W, not security-critical)
            //   file size (3 bytes, LSB first): 0x20 0x00 0x00  (32 bytes)
            val ccFileSize = 15
            val ccSize0 = (ccFileSize and 0xFF).toByte()
            val ccSize1 = ((ccFileSize shr 8) and 0xFF).toByte()
            val ccSize2 = ((ccFileSize shr 16) and 0xFF).toByte()
            val createCCBody = byteArrayOf(
                0x01,                   // fileNo
                0x03, 0xE1.toByte(),    // ISO FID = E103
                0x00,                   // comm settings (plain)
                0xEE.toByte(), 0xEE.toByte(), // access rights
                ccSize0, ccSize1, ccSize2
            )
            val respCreateCC = sendNative(0xCD.toByte(), createCCBody)
            val swCreateCC = respCreateCC.last().toInt() and 0xFF
            if (swCreateCC != 0x00 && swCreateCC != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForDualNdef: create CC file failed, status=0x${swCreateCC.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForDualNdef: create CC file ok (or duplicate), status=0x${swCreateCC.toString(16)}"
                )
            }

            // 5) Create NDEF file (fileNo=2, ISO FID E104, size = ndefCapacityBytes)
            val ndefSize = ndefCapacityBytes
            val ndefSize0 = (ndefSize and 0xFF).toByte()
            val ndefSize1 = ((ndefSize shr 8) and 0xFF).toByte()
            val ndefSize2 = ((ndefSize shr 16) and 0xFF).toByte()

            // For now: free read & write (0x00 0x00 per NFC Forum Type 4)
            val createNdefFileBody = byteArrayOf(
                0x02,                   // fileNo
                0x04, 0xE1.toByte(),    // ISO FID = E104
                0x00,                   // comm settings (plain)
                0xEE.toByte(), 0x00,             // access rights: free R/W
                ndefSize0, ndefSize1, ndefSize2
            )
            val respCreateNdef = sendNative(0xCD.toByte(), createNdefFileBody)
            val swCreateNdef = respCreateNdef.last().toInt() and 0xFF
            if (swCreateNdef != 0x00 && swCreateNdef != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForDualNdef: create NDEF file failed, status=0x${swCreateNdef.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForDualNdef: create NDEF file ok (or duplicate), status=0x${swCreateNdef.toString(16)}"
                )
            }

            // 6) Write CC contents (NFC Forum Type 4 mapping v2.0)
            //
            // CC layout:
            //   Byte 0-1: CCLEN (big-endian) -> 0x00 0x20
            //   Byte 2:   Mapping version -> 0x20
            //   Byte 3-4: MLe -> 0x00 0x3B
            //   Byte 5-6: MLc -> 0x00 0x34
            //   Byte 7:   T (NDEF File Control TLV) -> 0x04
            //   Byte 8:   L -> 0x06
            //   Byte 9-10: File ID (E104) -> 0xE1 0x04
            //   Byte 11-12: Max NDEF size (big-endian) = ndefCapacityBytes
            //   Byte 13: Read access  -> 0x00 (no security)
            //   Byte 14: Write access -> 0x00 (no security)
            val maxNdefLenHi = ((ndefCapacityBytes shr 8) and 0xFF).toByte()
            val maxNdefLenLo = (ndefCapacityBytes and 0xFF).toByte()

            val cc = ByteArray(ccFileSize) { 0 }
            cc[0]  = 0x00
            cc[1]  = 0x0f                // CCLEN = 15
            cc[2]  = 0x20                // Mapping version 2.0
            cc[3]  = 0x00
            cc[4]  = 0x3B                // MLe
            cc[5]  = 0x00
            cc[6]  = 0x34                // MLc
            cc[7]  = 0x04                // T = NDEF File Control TLV
            cc[8]  = 0x06                // L = 6
            cc[9]  = 0xE1.toByte()
            cc[10] = 0x04                // File ID = E104
            cc[11] = maxNdefLenHi
            cc[12] = maxNdefLenLo
            cc[13] = 0x00                // read access
            cc[14] = 0xFF.toByte()               // write access

            // Use our existing StandardFile writer (by fileNo)
            val ccOk = writeStandardFileInCurrentApp(0x01, cc)
            if (!ccOk) {
                Log.e(TAG, "lowLevelFormatPiccForDualNdef: writing CC file failed")
                return false
            }

            // 7) Seed NDEF file:
            // NDEF file contents = [NLEN (2 bytes BE)] + [NDEF message] + padding zeros
            val ndefRecord = buildMimeNdefRecord(seedMimeType, seedPayload)
            val ndefMsgLen = ndefRecord.size
            if (ndefMsgLen + 2 > ndefCapacityBytes) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForDualNdef: seed message too large ($ndefMsgLen) for capacity $ndefCapacityBytes"
                )
                return false
            }

            val ndefFileBytes = ByteArray(ndefCapacityBytes) { 0 }
            ndefFileBytes[0] = ((ndefMsgLen shr 8) and 0xFF).toByte()
            ndefFileBytes[1] = (ndefMsgLen and 0xFF).toByte()
            System.arraycopy(ndefRecord, 0, ndefFileBytes, 2, ndefMsgLen)

            val ndefOk = writeStandardFileInCurrentApp(0x02, ndefFileBytes)
            if (!ndefOk) {
                Log.e(TAG, "lowLevelFormatPiccForDualNdef: writing NDEF file failed")
                return false
            }

            Log.d(TAG, "lowLevelFormatPiccForDualNdef: completed successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "lowLevelFormatPiccForDualNdef failed", e)
            false
        }
    }

    /**
     * Send a raw DESFire native command (CLA=0x90) using IsoDep.
     *
     * @param ins   Instruction byte (e.g. 0xCA, 0xCD, 0x5A, etc.)
     * @param data  Payload (P3 bytes). Lc is derived from data.size.
     * @return      Full response including status bytes; last byte is status code (0x00 = OK).
     */
    private fun sendNative(ins: Byte, data: ByteArray = ByteArray(0)): ByteArray {
        val lc = data.size
        val apdu = ByteArray(5 + lc + 1) // CLA INS P1 P2 Lc [data] Le
        var i = 0
        apdu[i++] = 0x90.toByte()  // CLA
        apdu[i++] = ins            // INS
        apdu[i++] = 0x00           // P1
        apdu[i++] = 0x00           // P2
        apdu[i++] = lc.toByte()    // Lc
        if (lc > 0) {
            System.arraycopy(data, 0, apdu, i, lc)
            i += lc
        }
        apdu[i] = 0x00             // Le

        Log.d(TAG, "sendNative: INS=0x${(ins.toInt() and 0xFF).toString(16)}, Lc=$lc")
        val resp = isoDep.transceive(apdu)
        if (resp.isNotEmpty()) {
            Log.d(
                TAG,
                "sendNative resp: len=${resp.size}, lastStatus=0x${(resp.last().toInt() and 0xFF).toString(16)}"
            )
        } else {
            Log.e(TAG, "sendNative: empty response")
        }
        return resp
    }

    fun requiredType4Capacity(mimeType: String, payload: ByteArray): Int {
        val record = buildMimeNdefRecord(mimeType, payload)
        val nlenPlusMsg = 2 + record.size
        return nlenPlusMsg
    }

    /** Pick a decent NDEF file size (E104 capacity) with headroom + alignment. */
    fun chooseNdefCapacity(requiredBytes: Int): Int {
        val headroom = 128
        val minSize  = 512
        val align    = 32
        val base = max(minSize, requiredBytes + headroom)
        return ((base + (align - 1)) / align) * align
    }

    /** Quick check without writing: does RO message fit in current E104 capacity? */
    fun canWriteType4NdefRo(mimeType: String, payload: ByteArray): Boolean {
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) return false
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) return false

            val fs = desfire.getFileSettings(FILE_NDEF.toInt()) as? StandardDesfireFile ?: return false
            val capacity = fs.fileSize
            val required = requiredType4Capacity(mimeType, payload)
            required <= capacity
        } catch (_: Exception) {
            false
        }
    }


    companion object {
        private const val TAG = "NDEFHelper"

        // Private RW app
        private val IPS_AID: ByteArray = byteArrayOf(0x44, 0x55, 0x66) // 0x665544 LE
        private val MASTER_AID: ByteArray = byteArrayOf(0x00, 0x00, 0x00)
        private val NDEF_APP_AID: ByteArray = byteArrayOf(0x01, 0x00, 0x00) // NFC Forum NDEF app (AN11004)

        // Only one file in this app: RW extra NDEF-like blob
        private const val FILE_NDEF: Byte = 0x02   // NDEF data file inside 000001
        private const val FILE_EXTRA: Byte = 0x01

        // Default 8-byte DES key all zeros
        private val DEFAULT_DES_KEY = ByteArray(8) { 0x00 }

        // Key layout (same idea as DesfireHelper, but local here)
        private const val APPLICATION_MASTER_KEY_SETTINGS: Byte = 0x0F
        private const val APPLICATION_KEY_COUNT: Byte = 5

        private const val KEYNO_MASTER: Byte = 0x00
        private const val KEYNO_RW: Byte     = 0x01
        private const val KEYNO_CAR: Byte    = 0x02
        private const val KEYNO_R: Byte      = 0x03
        private const val KEYNO_W: Byte      = 0x04

        private const val MIN_EXTRA_FILE_SIZE = 256

        /**
         * Build a single-record NDEF message with TNF=Media-type (0x02) containing:
         *  - Type: mimeType (US-ASCII)
         *  - Payload: payload (raw bytes)
         *
         * Produces:
         *  - SR=1 (1-byte payload length) if payload < 256
         *  - SR=0 (4-byte payload length) otherwise
         *
         * No ID field (IL=0).
         */
        fun buildMimeNdefRecord(mimeType: String, payload: ByteArray): ByteArray {
            val typeBytes = mimeType.toByteArray(Charsets.US_ASCII)
            val typeLen = typeBytes.size
            val payloadLen = payload.size

            val isShort = payloadLen < 256

            // TNF for media-type
            val tnfMedia = 0x02

            // Header bits:
            // MB=1 (0x80), ME=1 (0x40), CF=0, SR=0/1 (0x10), IL=0, TNF=0x02
            var header = 0
            header = header or 0x80  // MB
            header = header or 0x40  // ME
            if (isShort) header = header or 0x10 // SR
            header = header or tnfMedia

            val headerByte = header.toByte()

            return if (isShort) {
                // Short record:
                // [HDR][TYPE_LEN][PAYLOAD_LEN(1)][TYPE...][PAYLOAD...]
                val result = ByteArray(3 + typeLen + payloadLen)
                var i = 0
                result[i++] = headerByte
                result[i++] = typeLen.toByte()
                result[i++] = payloadLen.toByte()
                System.arraycopy(typeBytes, 0, result, i, typeLen)
                i += typeLen
                System.arraycopy(payload, 0, result, i, payloadLen)
                result
            } else {
                // Normal record:
                // [HDR][TYPE_LEN][PAYLOAD_LEN(4)][TYPE...][PAYLOAD...]
                val result = ByteArray(6 + typeLen + payloadLen)
                var i = 0
                result[i++] = headerByte
                result[i++] = typeLen.toByte()
                result[i++] = ((payloadLen ushr 24) and 0xFF).toByte()
                result[i++] = ((payloadLen ushr 16) and 0xFF).toByte()
                result[i++] = ((payloadLen ushr 8) and 0xFF).toByte()
                result[i++] = (payloadLen and 0xFF).toByte()
                System.arraycopy(typeBytes, 0, result, i, typeLen)
                i += typeLen
                System.arraycopy(payload, 0, result, i, payloadLen)
                result
            }
        }


        /**
         * Connect to a DESFire EVx tag using IsoDep and wrap it for "dual section" operations.
         */
        fun connect(tag: Tag, debug: Boolean = false): NDEFHelper? {
            val isoDep = IsoDep.get(tag)
            if (isoDep == null) {
                Log.w(TAG, "Tag does not support IsoDep – not a DESFire EVx card")
                return null
            }

            return try {
                isoDep.timeout = 5000
                isoDep.connect()

                val isoDepWrapper = DefaultIsoDepWrapper(isoDep)
                val adapter = DESFireAdapter(isoDepWrapper, /*print*/ debug)

                val desfire = DESFireEV1().apply {
                    setAdapter(adapter)
                    setPrint(debug)
                }

                NDEFHelper(isoDep, desfire)
            } catch (e: Exception) {
                Log.e(TAG, "Error connecting to DESFire tag", e)
                try { isoDep.close() } catch (_: Exception) {}
                null
            }
        }

        /**
         * Destructive helper:
         *
         *  1. Connects via NDEFHelper (DESFire / IsoDep)
         *  2. formatPICC() – wipes the card completely
         *  3. Uses Android's NdefFormatable to create a standard Type-4 NDEF layout
         *     with an initial "seed" NDEF message.
         *
         * Result:
         *  - Card is now a valid NDEF tag (Ndef.get(tag) will work).
         *  - Exact NDEF file size is decided by Android's formatter and may be large.
         *
         * This is intended as a recovery / preparation step before using Write Dual NDEF.
         */
        fun formatPiccForDualNdef(
            tag: Tag,
            debug: Boolean = false,
            seedMimeType: String = "application/x.nps.v1-0",
            seedPayload: ByteArray = """{"type":"seed","msg":"Initial NDEF"}""".toByteArray(),
            ndefCapacityBytes: Int = 2048  // <= 2KB NDEF file, rest EEPROM free
        ): Boolean {
            val helper = connect(tag, debug)
            if (helper == null) {
                Log.e(TAG, "formatPiccForDualNdef: failed to connect via NDEFHelper (IsoDep)")
                return false
            }

            return try {
                helper.lowLevelFormatPiccForDualNdef(
                    seedMimeType = seedMimeType,
                    seedPayload = seedPayload,
                    ndefCapacityBytes = ndefCapacityBytes
                )
            } finally {
                helper.close()
            }
        }

    }
}