package uk.meds.ipsnfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile
import nfcjlib.core.DESFireAdapter
import nfcjlib.core.DESFireEV1
import nfcjlib.core.KeyType
import kotlin.math.min

data class NatoPayload(
    val npsPayload: ByteArray,
    val extraPayload: ByteArray
)

/**
 * NATOHelper:
 *
 * Implements the "pure" NATO spec layout:
 *
 *  - Single NDEF Tag application (AID 000001).
 *  - Inside that application:
 *      File 1 (E103): CC file, 32 bytes, with TWO TLVs
 *          - TLV 1 -> NDEF file for NPS (E104)
 *          - TLV 2 -> NDEF file for EXTRA (E105)
 *      File 2 (E104): NPS NDEF file (read-only, written by issuer)
 *      File 3 (E105): EXTRA NDEF file (read/write)
 *
 * Both NPS and EXTRA are stored as NFC Forum NDEF files:
 *
 *  [0..1] = NLEN (2 bytes, big-endian)
 *  [2..]  = NDEF message (here: a single MIME record)
 */
class NATOHelper private constructor(
    private val isoDep: IsoDep,
    private val desfire: DESFireEV1
) {

    fun close() {
        try {
            if (isoDep.isConnected) isoDep.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing IsoDep", e)
        }
    }

    // -------------------------------------------------------------------------
    // Public high-level API
    // -------------------------------------------------------------------------


    /**
     * Write BOTH NPS (RO) and EXTRA (RW) payloads into the NATO layout.
     *
     * Assumes the card has already been formatted with formatPiccForNatoNdef().
     */
    fun writeNatoPayloads(
        npsMimeType: String,
        npsPayload: ByteArray,
        extraMimeType: String,
        extraPayload: ByteArray
    ): Boolean {
        return try {
            // Calculate how many bytes we actually need in each file
            val npsNeed   = roundUp(requiredType4FileBytes(npsMimeType, npsPayload) + 16, 64)
            val extraNeed = roundUp(requiredType4FileBytes(extraMimeType, extraPayload) + 16, 64)

            // Ensure NATO NDEF app exists and files are big enough (may reformat if needed)
            if (!ensureNatoCapacities(npsNeed, extraNeed)) {
                Log.e(TAG, "writeNatoPayloads: ensureNatoCapacities failed")
                return false
            }

            // Select NATO NDEF app (000001)
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "writeNatoPayloads: failed to select NDEF app (000001)")
                return false
            }

            // Write NPS and EXTRA (writeNdefFileInCurrentApp checks size again)
            val npsOk = writeNdefFileInCurrentApp(FILE_NPS, npsMimeType, npsPayload)
            if (!npsOk) {
                Log.e(TAG, "writeNatoPayloads: failed to write NPS file")
                return false
            }

            if (!lockE104ReadFreeWriteBlocked()) {
                Log.e(TAG, "writeNatoPayloads: failed to lock E104")
                return false
            }

            val extraOk = writeNdefFileInCurrentApp(FILE_EXTRA, extraMimeType, extraPayload)
            if (!extraOk) {
                Log.e(TAG, "writeNatoPayloads: failed to write EXTRA file")
                return false
            }

            true
        } catch (e: Exception) {
            Log.e(TAG, "writeNatoPayloads failed", e)
            false
        }
    }

    /**
     * Read BOTH NPS and EXTRA payloads.
     *
     * Returns NatoPayload where:
     *  - npsPayload   = MIME payload from file E104
     *  - extraPayload = MIME payload from file E105
     *
     * (We parse NDEF, but only return the inner payload bytes.)
     */
    fun readNatoPayloads(): NatoPayload? {
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "readNatoPayloads: failed to select NDEF app (000001)")
                return null
            }

            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "readNatoPayloads: app master auth failed")
                return null
            }

            val npsBytes   = readWholeFile(FILE_NPS)   ?: return null
            val extraBytes = readWholeFile(FILE_EXTRA) ?: return null

            val npsPayload   = extractNdefMimePayload(npsBytes)   ?: return null
            val extraPayload = extractNdefMimePayload(extraBytes) ?: return null

            NatoPayload(npsPayload = npsPayload, extraPayload = extraPayload)
        } catch (e: Exception) {
            Log.e(TAG, "readNatoPayloads failed", e)
            null
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------
    private fun ensureNatoCapacities(npsCapacityBytes: Int, extraCapacityBytes: Int): Boolean {
        // Try to inspect current layout; if missing or too small -> do destructive rebuild
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.w(TAG, "ensureNatoCapacities: NDEF app not present, creating fresh NATO layout")
                return lowLevelFormatPiccForNatoNdef(
                    seedNpsMimeType = "application/x.nps.v1-0",
                    seedNpsPayload = """{"type":"nps-seed","msg":"seed"}""".toByteArray(),
                    npsCapacityBytes = npsCapacityBytes,
                    extraCapacityBytes = extraCapacityBytes
                )
            }

            val fsNps = desfire.getFileSettings(FILE_NPS.toInt()) as? StandardDesfireFile
            val fsExtra = desfire.getFileSettings(FILE_EXTRA.toInt()) as? StandardDesfireFile

            if (fsNps == null || fsExtra == null) {
                Log.w(TAG, "ensureNatoCapacities: files missing, rebuilding NATO layout")
                return lowLevelFormatPiccForNatoNdef(
                    seedNpsMimeType = "application/x.nps.v1-0",
                    seedNpsPayload = """{"type":"nps-seed","msg":"seed"}""".toByteArray(),
                    npsCapacityBytes = npsCapacityBytes,
                    extraCapacityBytes = extraCapacityBytes
                )
            }

            val curNps = fsNps.fileSize
            val curExtra = fsExtra.fileSize

            val needRebuild = (curNps < npsCapacityBytes) || (curExtra < extraCapacityBytes)
            if (!needRebuild) {
                Log.d(TAG, "ensureNatoCapacities: OK (NPS=$curNps, EXTRA=$curExtra)")
                return true
            }

            Log.w(
                TAG,
                "ensureNatoCapacities: too small (NPS=$curNps need=$npsCapacityBytes, EXTRA=$curExtra need=$extraCapacityBytes) -> rebuilding"
            )

            lowLevelFormatPiccForNatoNdef(
                seedNpsMimeType = "application/x.nps.v1-0",
                seedNpsPayload = """{"type":"nps-seed","msg":"seed"}""".toByteArray(),
                npsCapacityBytes = npsCapacityBytes,
                extraCapacityBytes = extraCapacityBytes
            )
        } catch (e: Exception) {
            Log.e(TAG, "ensureNatoCapacities failed", e)
            false
        }
    }


    private fun requiredType4FileBytes(mimeType: String, payload: ByteArray): Int {
        val record = buildMimeNdefRecord(mimeType, payload)
        return 2 + record.size // NLEN(2) + NDEF record bytes
    }

    // nice-to-have: round up so we don’t reformat on tiny growth
    private fun roundUp(value: Int, step: Int): Int {
        if (step <= 0) return value
        return ((value + step - 1) / step) * step
    }

    /**
     * Format PICC and build full NATO layout using native commands:
     *
     * 1) formatPICC()  -> erase all apps/files
     * 2) Create NFC Forum NDEF application (AID 000001, ISO DF name D2760000850101)
     * 3) Inside that app, create:
     *      - CC file   (fileNo=1, ISO FID E103, size 32)
     *      - NPS file  (fileNo=2, ISO FID E104, size = npsCapacityBytes, RO)
     *      - EXTRA file(fileNo=3, ISO FID E105, size = extraCapacityBytes, RW)
     * 4) Write CC with TWO TLVs (NPS + EXTRA).
     * 5) Seed NPS file with initial NDEF MIME record.
     */
    fun lowLevelFormatPiccForNatoNdef(
        seedNpsMimeType: String,
        seedNpsPayload: ByteArray,
        npsCapacityBytes: Int,
        extraCapacityBytes: Int
    ): Boolean {
        return try {
            // 1) Full destructive format of PICC
            if (!formatPiccInternal()) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: formatPiccInternal() failed")
                return false
            }

            // 2) Create NDEF application (AID = 000001) via native 0xCA
            val createNdefAppBody = byteArrayOf(
                0x01, 0x00, 0x00,       // AID = 000001 (LSB first)
                0x0F,                   // key settings
                0x21,                   // app settings (ISO support)
                0x05, 0x01,             // 5 keys, key type DES
                0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01 // ISO DF name
            )
            val respCreateApp = sendNative(0xCA.toByte(), createNdefAppBody)
            val swCreateApp = respCreateApp.last().toInt() and 0xFF
            if (swCreateApp != 0x00 && swCreateApp != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNatoNdef: create NDEF app failed, status=0x${swCreateApp.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForNatoNdef: create NDEF app ok (or duplicate), status=0x${swCreateApp.toString(16)}"
                )
            }

            // 3) Select NDEF app and authenticate master key
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: failed to select NDEF app (000001)")
                return false
            }
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: app master auth failed")
                return false
            }

            // 4) Create CC file (fileNo=1, ISO FID E103, size 32)
            val ccFileSize = CC_FILE_SIZE
            val ccSize0 = (ccFileSize and 0xFF).toByte()
            val ccSize1 = ((ccFileSize shr 8) and 0xFF).toByte()
            val ccSize2 = ((ccFileSize shr 16) and 0xFF).toByte()

            val createCCBody = byteArrayOf(
                FILE_CC,                // fileNo = 0x01
                0x03, 0xE1.toByte(),    // ISO FID = E103
                0x00,                   // comm settings (plain)
                0xEE.toByte(), 0xEE.toByte(), // access rights (free R/W for CC)
                ccSize0, ccSize1, ccSize2
            )
            val respCreateCC = sendNative(0xCD.toByte(), createCCBody)
            val swCreateCC = respCreateCC.last().toInt() and 0xFF
            if (swCreateCC != 0x00 && swCreateCC != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNatoNdef: create CC file failed, status=0x${swCreateCC.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForNatoNdef: create CC file ok (or duplicate), status=0x${swCreateCC.toString(16)}"
                )
            }

            // 5) Create NPS NDEF file (fileNo=2, ISO FID E104)
            val npsSize = npsCapacityBytes
            val npsSize0 = (npsSize and 0xFF).toByte()
            val npsSize1 = ((npsSize shr 8) and 0xFF).toByte()
            val npsSize2 = ((npsSize shr 16) and 0xFF).toByte()

            // Access rights per spec suggestion: read all (0xE0), write via key 0 (0x00)
            val createNpsBody = byteArrayOf(
                FILE_NPS,               // fileNo = 0x02
                0x04, 0xE1.toByte(),    // ISO FID = E104
                0x00,                   // comm settings (plain)
                0xEE.toByte(), 0xEE.toByte(), // TEMP rights: master key for everything
                npsSize0, npsSize1, npsSize2
            )
            val respCreateNps = sendNative(0xCD.toByte(), createNpsBody)
            val swCreateNps = respCreateNps.last().toInt() and 0xFF
            if (swCreateNps != 0x00 && swCreateNps != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNatoNdef: create NPS file failed, status=0x${swCreateNps.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForNatoNdef: create NPS file ok (or duplicate), status=0x${swCreateNps.toString(16)}"
                )
            }

            // 6) Compute EXTRA size from card free memory, then create EXTRA NDEF file (fileNo=3, ISO FID E105)

// FreeMemory is PICC-level: select 000000 first
            val PICC_AID = byteArrayOf(0x00, 0x00, 0x00)
            if (!desfire.selectApplication(PICC_AID)) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: failed to select PICC AID for freeMemory")
                return false
            }

            val freeMemRaw = desfire.freeMemory()
            if (freeMemRaw == null || freeMemRaw.size < 3) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: freeMemory() returned null/short")
                return false
            }
            val remaining = (freeMemRaw[0].toInt() and 0xFF) or
                    ((freeMemRaw[1].toInt() and 0xFF) shl 8) or
                    ((freeMemRaw[2].toInt() and 0xFF) shl 16)

// Leave some safety room; align to 32 bytes (DESFire alloc granularity)
            val safety = 128
            val extraSize = (((remaining - safety).coerceAtLeast(256)) / 32) * 32

// Back into NDEF app and re-auth
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: failed to re-select NDEF app")
                return false
            }
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: app master auth failed (before create EXTRA)")
                return false
            }

// Create EXTRA file sized to "rest of card"
            val extraSize0 = (extraSize and 0xFF).toByte()
            val extraSize1 = ((extraSize shr 8) and 0xFF).toByte()
            val extraSize2 = ((extraSize shr 16) and 0xFF).toByte()

            val createExtraBody = byteArrayOf(
                FILE_EXTRA,
                0x05, 0xE1.toByte(),        // ISO FID = E105
                0x00,                       // comm plain
                0xEE.toByte(), 0xEE.toByte(),// free R/W
                extraSize0, extraSize1, extraSize2
            )

            val respCreateExtra = sendNative(0xCD.toByte(), createExtraBody)
            val swCreateExtra = respCreateExtra.last().toInt() and 0xFF
            if (swCreateExtra != 0x00 && swCreateExtra != 0xDE) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: create EXTRA file failed, status=0x${swCreateExtra.toString(16)}")
                return false
            } else {
                Log.d(TAG, "lowLevelFormatPiccForNatoNdef: create EXTRA file ok (or duplicate), extraSize=$extraSize")
            }

            // 7) Write CC contents with TWO TLVs
            val maxNpsLenHi   = ((npsCapacityBytes shr 8) and 0xFF).toByte()
            val maxNpsLenLo   = (npsCapacityBytes and 0xFF).toByte()
            val maxExtraLenHi = ((extraSize shr 8) and 0xFF).toByte()
            val maxExtraLenLo = (extraSize and 0xFF).toByte()

            val cc = ByteArray(CC_FILE_SIZE) { 0 }
// Header
            cc[0] = 0x00
            cc[1] = 0x17               // CCLEN = 32
            cc[2] = 0x20               // Mapping version 2.0
            cc[3] = 0x00
            cc[4] = 0x3B               // MLe
            cc[5] = 0x00
            cc[6] = 0x34               // MLc

// TLV 1: NPS file (E104)
            cc[7]  = 0x04              // T = NDEF File Control TLV
            cc[8]  = 0x06              // L = 6
            cc[9]  = 0xE1.toByte()
            cc[10] = 0x04              // File ID = E104
            cc[11] = maxNpsLenHi
            cc[12] = maxNpsLenLo
            cc[13] = 0x00              // read access
            cc[14] = 0xFF.toByte()     // write not allowed (example per spec)

// TLV 2: EXTRA file (E105)
            cc[15] = 0x04              // T = NDEF File Control TLV
            cc[16] = 0x06              // L = 6
            cc[17] = 0xE1.toByte()
            cc[18] = 0x05              // File ID = E105
            cc[19] = maxExtraLenHi
            cc[20] = maxExtraLenLo
            cc[21] = 0x00              // read access
            cc[22] = 0x00              // write access (free)

            val ccOk = writeStandardFileInCurrentApp(FILE_CC, cc)
            if (!ccOk) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: writing CC file failed")
                return false
            }

            // 8) Seed NPS NDEF file (NO ZERO PADDING)
            // Build the full NDEF message bytes (record(s))
            val ndefRecord = buildMimeNdefRecord(seedNpsMimeType, seedNpsPayload)
            val ndefMsgLen = ndefRecord.size
            if (ndefMsgLen + 2 > npsCapacityBytes) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNatoNdef: seed message too large ($ndefMsgLen) for NPS capacity $npsCapacityBytes"
                )
                return false
            }

            // Write only: NLEN(2) + message bytes
            val seeded = ByteArray(2 + ndefMsgLen)
            seeded[0] = ((ndefMsgLen shr 8) and 0xFF).toByte()
            seeded[1] = (ndefMsgLen and 0xFF).toByte()
            System.arraycopy(ndefRecord, 0, seeded, 2, ndefMsgLen)

            // (Optional but nice) first set NLEN=0 then write full content.
            // It avoids any partial-read weirdness during write windows.
            val nlenZeroOk = writeStandardFileSlice(FILE_NPS, 0, byteArrayOf(0x00, 0x00))
            if (!nlenZeroOk) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: pre-write NLEN=0 failed")
                return false
            }

            val npsWriteOk = writeStandardFileSlice(FILE_NPS, 0, seeded)
            if (!npsWriteOk) {
                Log.e(TAG, "lowLevelFormatPiccForNatoNdef: writing seeded NPS file failed")
                return false
            }

            Log.d(TAG, "lowLevelFormatPiccForNatoNdef: completed successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "lowLevelFormatPiccForNatoNdef failed", e)
            false
        }
    }

    private fun lockE104ReadFreeWriteBlocked(): Boolean {
        // Desired final profile:
        // Read key = E (free)
        // Write key = F (blocked)
        // Read/Write key = F (blocked)
        // Change key = F (blocked)
        //
        // AccessRights bytes are: [ (RW<<4 | Change), (Read<<4 | Write) ]
        val ar0 = 0xFF.toByte() // RW=F, Change=F
        val ar1 = 0xEF.toByte() // Read=E, Write=F

        val body = byteArrayOf(
            FILE_NPS,
            0x00,        // comm settings plain
            ar0, ar1
        )

        val resp = sendNative(0x5F.toByte(), body)
        val sw = resp.last().toInt() and 0xFF
        return if (sw == 0x00) {
            Log.d(TAG, "lockE104ReadFreeWriteBlocked: locked E104 (FF EF)")
            true
        } else {
            Log.e(TAG, "lockE104ReadFreeWriteBlocked: failed status=0x${sw.toString(16)}")
            false
        }
    }

    fun writeStandardFileSlice(fileNo: Byte, offset: Int, data: ByteArray): Boolean {
        // payload: fileNo (1) + offset (3 LSB) + length (3 LSB) + data (N)
        val len = data.size
        val payload = ByteArray(1 + 3 + 3 + len)
        payload[0] = fileNo

        // offset (3 bytes LSB)
        payload[1] = (offset and 0xFF).toByte()
        payload[2] = ((offset shr 8) and 0xFF).toByte()
        payload[3] = ((offset shr 16) and 0xFF).toByte()

        // length (3 bytes LSB)
        payload[4] = (len and 0xFF).toByte()
        payload[5] = ((len shr 8) and 0xFF).toByte()
        payload[6] = ((len shr 16) and 0xFF).toByte()

        System.arraycopy(data, 0, payload, 7, len)

        return try {
            desfire.writeData(payload)
        } catch (e: Exception) {
            Log.e(TAG, "writeStandardFileSlice: writeData failed (fileNo=$fileNo, offset=$offset, len=$len)", e)
            false
        }
    }

    // -------------------------------------------------------------------------
    // Shared internal utilities
    // -------------------------------------------------------------------------

    private fun readWholeFile(fileNo: Byte): ByteArray? {
        val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile
            ?: run {
                Log.e(TAG, "readWholeFile($fileNo): not a Standard file / not found")
                return null
            }

        val size = fs.fileSize
        val data = desfire.readData(fileNo, 0, size)
        if (data == null) {
            Log.e(
                TAG,
                "readWholeFile($fileNo): readData returned null " +
                        "(code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})"
            )
        }
        return data
    }

    /**
     * Parse an NDEF file (as per NFC Forum Type 4) and return the payload of the
     * first MIME record:
     *
     *  [0..1] = NLEN (big endian)
     *  [2..]  = NDEF message (we assume single record)
     */
    private fun extractNdefMimePayload(fileBytes: ByteArray): ByteArray? {
        if (fileBytes.size < 3) {
            Log.e(TAG, "extractNdefMimePayload: file too small")
            return null
        }

        val nlen = ((fileBytes[0].toInt() and 0xFF) shl 8) or
                (fileBytes[1].toInt() and 0xFF)

        if (nlen == 0 || 2 + nlen > fileBytes.size) {
            Log.e(TAG, "extractNdefMimePayload: invalid NLEN=$nlen")
            return null
        }

        var idx = 2
        val header = fileBytes[idx].toInt() and 0xFF
        idx++

        val sr = (header and 0x10) != 0
        val typeLen = fileBytes[idx].toInt() and 0xFF
        idx++

        val payloadLen: Int = if (sr) {
            fileBytes[idx].toInt() and 0xFF
        } else {
            // 4-byte payload length
            ((fileBytes[idx].toInt() and 0xFF) shl 24) or
                    ((fileBytes[idx + 1].toInt() and 0xFF) shl 16) or
                    ((fileBytes[idx + 2].toInt() and 0xFF) shl 8) or
                    (fileBytes[idx + 3].toInt() and 0xFF)
        }
        idx += if (sr) 1 else 4

        // Type field
        idx += typeLen

        if (idx + payloadLen > 2 + nlen) {
            Log.e(TAG, "extractNdefMimePayload: payloadLen=$payloadLen exceeds NLEN=$nlen")
            return null
        }

        return fileBytes.copyOfRange(idx, idx + payloadLen)
    }

    /**
     * Write an NDEF file in the currently selected app:
     *  - Auth with master key
     *  - Read file size
     *  - Build [NLEN + NDEF message] and pad to file size
     */
    private fun writeNdefFileInCurrentApp(
        fileNo: Byte,
        mimeType: String,
        payload: ByteArray
    ): Boolean {
        // 1) Build NDEF MIME record
        val ndefRecord = buildMimeNdefRecord(mimeType, payload)
        val msgLen = ndefRecord.size

        // 2) Authenticate master, get file size
        val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
        if (!appAuthOk) {
            Log.e(TAG, "writeNdefFileInCurrentApp($fileNo): app master auth failed")
            return false
        }

        val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile
            ?: run {
                Log.e(TAG, "writeNdefFileInCurrentApp($fileNo): not a Standard file / not found")
                return false
            }

        val fileSize = fs.fileSize
        if (msgLen + 2 > fileSize) {
            Log.e(
                TAG,
                "writeNdefFileInCurrentApp($fileNo): message too large ($msgLen) for file size $fileSize"
            )
            return false
        }

        val buffer = ByteArray(fileSize) { 0 }
        buffer[0] = ((msgLen shr 8) and 0xFF).toByte()
        buffer[1] = (msgLen and 0xFF).toByte()
        System.arraycopy(ndefRecord, 0, buffer, 2, msgLen)

        return writeStandardFileInCurrentApp(fileNo, buffer)
    }

    /**
     * Write a full Standard Data File in the currently selected application.
     */
    private fun writeStandardFileInCurrentApp(fileNo: Byte, data: ByteArray): Boolean {
        return try {
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "writeStandardFileInCurrentApp($fileNo): app master auth failed")
                return false
            }

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
                ?: throw RuntimeException("writeStandardFileInCurrentApp($fileNo): writeToStandardFile returned null")

            val ok = desfire.writeData(payload)
            Log.d(
                TAG,
                "writeStandardFileInCurrentApp($fileNo) -> $ok code=${desfire.code.toString(16)} desc=${desfire.codeDesc}"
            )
            ok
        } catch (e: Exception) {
            Log.e(TAG, "writeStandardFileInCurrentApp($fileNo) failed", e)
            false
        }
    }

    /**
     * Full PICC format (destructive): select 000000, auth, formatPICC().
     */
    private fun formatPiccInternal(): Boolean {
        return try {
            if (!desfire.selectApplication(MASTER_AID)) {
                Log.e(TAG, "formatPiccInternal: failed to select master application")
                false
            } else {
                val authOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
                if (!authOk) {
                    Log.e(TAG, "formatPiccInternal: PICC master auth failed")
                    false
                } else {
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
     * Send a raw DESFire native command (CLA=0x90) using IsoDep.
     */
    private fun sendNative(ins: Byte, data: ByteArray = ByteArray(0)): ByteArray {
        val lc = data.size
        val apdu = ByteArray(5 + lc + 1)
        var i = 0
        apdu[i++] = 0x90.toByte()  // CLA
        apdu[i++] = ins
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

    private fun freeMemoryBytes(): Int {
        // freeMemory() returns 3 bytes, LSB first
        val b = desfire.freeMemory() ?: return 0
        return (b[0].toInt() and 0xFF) or
                ((b[1].toInt() and 0xFF) shl 8) or
                ((b[2].toInt() and 0xFF) shl 16)
    }

    private fun roundDown(value: Int, step: Int): Int {
        if (step <= 0) return value
        return (value / step) * step
    }

    private fun writeStandardFilePartialInCurrentApp(fileNo: Byte, offset: Int, data: ByteArray): Boolean {
        // Payload format expected by DESFireEV1.write():
        // [fileNo][offset(3 LSB)][len(3 LSB)][data...]
        val off = offset
        val len = data.size

        val payload = ByteArray(1 + 3 + 3 + len)
        var p = 0
        payload[p++] = fileNo
        // offset (LSB)
        payload[p++] = (off and 0xFF).toByte()
        payload[p++] = ((off shr 8) and 0xFF).toByte()
        payload[p++] = ((off shr 16) and 0xFF).toByte()
        // length (LSB)
        payload[p++] = (len and 0xFF).toByte()
        payload[p++] = ((len shr 8) and 0xFF).toByte()
        payload[p++] = ((len shr 16) and 0xFF).toByte()

        System.arraycopy(data, 0, payload, p, len)

        return desfire.writeData(payload)
    }


    // -------------------------------------------------------------------------
    // Static / companion stuff
    // -------------------------------------------------------------------------

    companion object {
        private const val TAG = "NATOHelper"

        private val MASTER_AID: ByteArray   = byteArrayOf(0x00, 0x00, 0x00)
        private val NDEF_APP_AID: ByteArray = byteArrayOf(0x01, 0x00, 0x00) // 000001

        private const val FILE_CC: Byte    = 0x01
        private const val FILE_NPS: Byte   = 0x02
        private const val FILE_EXTRA: Byte = 0x03

        private const val CC_FILE_SIZE = 23

        private val DEFAULT_DES_KEY = ByteArray(8) { 0x00 }

        private const val KEYNO_MASTER: Byte = 0x00

        /**
         * Build a single NDEF MIME record.
         * We support both SR=1 (payload <256) and SR=0 if payload is larger.
         */
        fun buildMimeNdefRecord(mimeType: String, payload: ByteArray): ByteArray {
            val typeBytes = mimeType.toByteArray(Charsets.US_ASCII)
            val typeLen = typeBytes.size
            val payloadLen = payload.size

            val sr = payloadLen < 256
            val tnfMedia =  0x02
            var header: Int = 0
            header = header or 0x80  // MB
            header = header or 0x40  // ME
            // CF = 0
            if (sr) header = header or 0x10 // SR
            // IL = 0
            header = header or tnfMedia

            val headerByte = header.toByte()

            return if (sr) {
                // Short record: 1-byte payload length
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
                // Normal record: 4-byte payload length
                val result = ByteArray(6 + typeLen + payloadLen)
                var i = 0
                result[i++] = headerByte
                result[i++] = typeLen.toByte()
                result[i++] = ((payloadLen shr 24) and 0xFF).toByte()
                result[i++] = ((payloadLen shr 16) and 0xFF).toByte()
                result[i++] = ((payloadLen shr 8) and 0xFF).toByte()
                result[i++] = (payloadLen and 0xFF).toByte()
                System.arraycopy(typeBytes, 0, result, i, typeLen)
                i += typeLen
                System.arraycopy(payload, 0, result, i, payloadLen)
                result
            }
        }

        /**
         * Connect to a DESFire EVx tag using IsoDep.
         */
        fun connect(tag: Tag, debug: Boolean = false): NATOHelper? {
            val isoDep = IsoDep.get(tag) ?: run {
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

                NATOHelper(isoDep, desfire)
            } catch (e: Exception) {
                Log.e(TAG, "Error connecting to DESFire tag", e)
                try { isoDep.close() } catch (_: Exception) {}
                null
            }
        }

        /**
         * Destructive NATO formatter:
         *
         *  1. Connect
         *  2. formatPICC()
         *  3. Create NATO layout (CC + NPS + EXTRA inside AID 000001)
         *  4. Seed NPS NDEF with a MIME record.
         */
        fun formatPiccForNatoNdef(
            tag: Tag,
            debug: Boolean = false,
            seedNpsMimeType: String = "application/x.nps.v1-0",
            seedNpsPayload: ByteArray = """{"type":"nps-seed","msg":"Initial NATO NPS"}""".toByteArray(),
            npsCapacityBytes: Int = 2048,
            extraCapacityBytes: Int = 2048
        ): Boolean {
            val helper = connect(tag, debug) ?: run {
                Log.e(TAG, "formatPiccForNatoNdef: failed to connect to tag")
                return false
            }

            return try {
                helper.lowLevelFormatPiccForNatoNdef(
                    seedNpsMimeType = seedNpsMimeType,
                    seedNpsPayload = seedNpsPayload,
                    npsCapacityBytes = npsCapacityBytes,
                    extraCapacityBytes = extraCapacityBytes
                )
            } finally {
                helper.close()
            }
        }
    }
}
