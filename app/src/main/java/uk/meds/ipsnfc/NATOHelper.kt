package uk.meds.ipsnfc

import android.nfc.Tag
import android.util.Log
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
 *      File 1 (E103): CC file, 23 bytes, with TWO TLVs
 *          - TLV 1 -> NDEF file for NPS (E104)
 *          - TLV 2 -> NDEF file for EXTRA (E105)
 *      File 2 (E104): NPS NDEF file (read-only, written by issuer)
 *      File 3 (E105): EXTRA NDEF file (read/write)
 */
class NATOHelper private constructor(
    private val transport: ApduTransport,
    private val desfire: DESFireEV1
) {

    fun close() {
        try {
            transport.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing transport", e)
        }
    }

    fun writeNatoPayloads(
        npsMimeType: String,
        npsPayload: ByteArray,
        extraMimeType: String,
        extraPayload: ByteArray
    ): Boolean {
        return try {
            val npsNeed   = roundUp(requiredType4FileBytes(npsMimeType, npsPayload) + 16, 64)
            val extraNeed = roundUp(requiredType4FileBytes(extraMimeType, extraPayload) + 16, 64)

            if (!ensureNatoCapacities(npsNeed, extraNeed)) {
                Log.e(TAG, "writeNatoPayloads: ensureNatoCapacities failed")
                return false
            }

            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "writeNatoPayloads: failed to select NDEF app (000001)")
                return false
            }

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

    private fun ensureNatoCapacities(npsCapacityBytes: Int, extraCapacityBytes: Int): Boolean {
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) {
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
                return lowLevelFormatPiccForNatoNdef(
                    seedNpsMimeType = "application/x.nps.v1-0",
                    seedNpsPayload = """{"type":"nps-seed","msg":"seed"}""".toByteArray(),
                    npsCapacityBytes = npsCapacityBytes,
                    extraCapacityBytes = extraCapacityBytes
                )
            }

            val curNps = fsNps.fileSize
            val curExtra = fsExtra.fileSize

            if (curNps < npsCapacityBytes || curExtra < extraCapacityBytes) {
                return lowLevelFormatPiccForNatoNdef(
                    seedNpsMimeType = "application/x.nps.v1-0",
                    seedNpsPayload = """{"type":"nps-seed","msg":"seed"}""".toByteArray(),
                    npsCapacityBytes = npsCapacityBytes,
                    extraCapacityBytes = extraCapacityBytes
                )
            }
            true
        } catch (e: Exception) {
            Log.e(TAG, "ensureNatoCapacities failed", e)
            false
        }
    }

    private fun requiredType4FileBytes(mimeType: String, payload: ByteArray): Int {
        val record = buildMimeNdefRecord(mimeType, payload)
        return 2 + record.size
    }

    private fun roundUp(value: Int, step: Int): Int {
        if (step <= 0) return value
        return ((value + step - 1) / step) * step
    }

    fun lowLevelFormatPiccForNatoNdef(
        seedNpsMimeType: String,
        seedNpsPayload: ByteArray,
        npsCapacityBytes: Int,
        extraCapacityBytes: Int
    ): Boolean {
        return try {
            if (!formatPiccInternal()) return false

            val createNdefAppBody = byteArrayOf(
                0x01, 0x00, 0x00,
                0x0F,
                0x21,
                0x05, 0x01,
                0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01
            )
            val respCreateApp = sendNative(0xCA.toByte(), createNdefAppBody)
            val swCreateApp = respCreateApp.last().toInt() and 0xFF
            if (swCreateApp != 0x00 && swCreateApp != 0xDE) return false

            if (!desfire.selectApplication(NDEF_APP_AID)) return false
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false

            val createCCBody = byteArrayOf(
                FILE_CC,
                0x03, 0xE1.toByte(),
                0x00,
                0xEE.toByte(), 0xEE.toByte(),
                (CC_FILE_SIZE and 0xFF).toByte(), 0x00, 0x00
            )
            val respCreateCC = sendNative(0xCD.toByte(), createCCBody)
            val swCreateCC = respCreateCC.last().toInt() and 0xFF
            if (swCreateCC != 0x00 && swCreateCC != 0xDE) return false

            val createNpsBody = byteArrayOf(
                FILE_NPS,
                0x04, 0xE1.toByte(),
                0x00,
                0xEE.toByte(), 0xEE.toByte(),
                (npsCapacityBytes and 0xFF).toByte(), ((npsCapacityBytes shr 8) and 0xFF).toByte(), ((npsCapacityBytes shr 16) and 0xFF).toByte()
            )
            val respCreateNps = sendNative(0xCD.toByte(), createNpsBody)
            if ((respCreateNps.last().toInt() and 0xFF) != 0x00) return false

            if (!desfire.selectApplication(byteArrayOf(0x00, 0x00, 0x00))) return false
            val freeMemRaw = desfire.freeMemory() ?: return false
            val remaining = (freeMemRaw[0].toInt() and 0xFF) or ((freeMemRaw[1].toInt() and 0xFF) shl 8) or ((freeMemRaw[2].toInt() and 0xFF) shl 16)
            val extraSize = (((remaining - 128).coerceAtLeast(256)) / 32) * 32

            if (!desfire.selectApplication(NDEF_APP_AID)) return false
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false

            val createExtraBody = byteArrayOf(
                FILE_EXTRA,
                0x05, 0xE1.toByte(),
                0x00,
                0xEE.toByte(), 0xEE.toByte(),
                (extraSize and 0xFF).toByte(), ((extraSize shr 8) and 0xFF).toByte(), ((extraSize shr 16) and 0xFF).toByte()
            )
            val respCreateExtra = sendNative(0xCD.toByte(), createExtraBody)
            if ((respCreateExtra.last().toInt() and 0xFF) != 0x00) return false

            val cc = ByteArray(CC_FILE_SIZE) { 0 }
            cc[0] = 0x00
            cc[1] = 0x17
            cc[2] = 0x20
            cc[3] = 0x00
            cc[4] = 0x3B
            cc[5] = 0x00
            cc[6] = 0x34
            cc[7]  = 0x04
            cc[8]  = 0x06
            cc[9]  = 0xE1.toByte()
            cc[10] = 0x04
            cc[11] = ((npsCapacityBytes shr 8) and 0xFF).toByte()
            cc[12] = (npsCapacityBytes and 0xFF).toByte()
            cc[13] = 0x00
            cc[14] = 0xFF.toByte()
            cc[15] = 0x04
            cc[16] = 0x06
            cc[17] = 0xE1.toByte()
            cc[18] = 0x05
            cc[19] = ((extraSize shr 8) and 0xFF).toByte()
            cc[20] = (extraSize and 0xFF).toByte()
            cc[21] = 0x00
            cc[22] = 0x00

            if (!writeStandardFileInCurrentApp(FILE_CC, cc)) return false

            val ndefRecord = buildMimeNdefRecord(seedNpsMimeType, seedNpsPayload)
            val ndefMsgLen = ndefRecord.size
            val seeded = ByteArray(2 + ndefMsgLen)
            seeded[0] = ((ndefMsgLen shr 8) and 0xFF).toByte()
            seeded[1] = (ndefMsgLen and 0xFF).toByte()
            System.arraycopy(ndefRecord, 0, seeded, 2, ndefMsgLen)

            if (!writeStandardFileSlice(FILE_NPS, 0, seeded)) return false

            true
        } catch (e: Exception) {
            Log.e(TAG, "lowLevelFormatPiccForNatoNdef failed", e)
            false
        }
    }

    private fun lockE104ReadFreeWriteBlocked(): Boolean {
        val body = byteArrayOf(FILE_NPS, 0x00, 0xFF.toByte(), 0xEF.toByte())
        val resp = sendNative(0x5F.toByte(), body)
        return (resp.last().toInt() and 0xFF) == 0x00
    }

    fun writeStandardFileSlice(fileNo: Byte, offset: Int, data: ByteArray): Boolean {
        val len = data.size
        val payload = ByteArray(1 + 3 + 3 + len)
        payload[0] = fileNo
        payload[1] = (offset and 0xFF).toByte()
        payload[2] = ((offset shr 8) and 0xFF).toByte()
        payload[3] = ((offset shr 16) and 0xFF).toByte()
        payload[4] = (len and 0xFF).toByte()
        payload[5] = ((len shr 8) and 0xFF).toByte()
        payload[6] = ((len shr 16) and 0xFF).toByte()
        System.arraycopy(data, 0, payload, 7, len)
        return try {
            desfire.writeData(payload)
        } catch (e: Exception) {
            false
        }
    }

    private fun readWholeFile(fileNo: Byte): ByteArray? {
        val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile ?: return null
        return desfire.readData(fileNo, 0, fs.fileSize)
    }

    private fun extractNdefMimePayload(fileBytes: ByteArray): ByteArray? {
        if (fileBytes.size < 3) return null
        val nlen = ((fileBytes[0].toInt() and 0xFF) shl 8) or (fileBytes[1].toInt() and 0xFF)
        if (nlen == 0 || 2 + nlen > fileBytes.size) return null
        var idx = 2
        val header = fileBytes[idx].toInt() and 0xFF
        idx++
        val sr = (header and 0x10) != 0
        val typeLen = fileBytes[idx].toInt() and 0xFF
        idx++
        val payloadLen: Int = if (sr) {
            fileBytes[idx].toInt() and 0xFF
        } else {
            ((fileBytes[idx].toInt() and 0xFF) shl 24) or ((fileBytes[idx + 1].toInt() and 0xFF) shl 16) or ((fileBytes[idx + 2].toInt() and 0xFF) shl 8) or (fileBytes[idx + 3].toInt() and 0xFF)
        }
        idx += if (sr) 1 else 4
        idx += typeLen
        if (idx + payloadLen > 2 + nlen) return null
        return fileBytes.copyOfRange(idx, idx + payloadLen)
    }

    private fun writeNdefFileInCurrentApp(fileNo: Byte, mimeType: String, payload: ByteArray): Boolean {
        val ndefRecord = buildMimeNdefRecord(mimeType, payload)
        val msgLen = ndefRecord.size
        if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false
        val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile ?: return false
        val fileSize = fs.fileSize
        if (msgLen + 2 > fileSize) return false
        val buffer = ByteArray(fileSize) { 0 }
        buffer[0] = ((msgLen shr 8) and 0xFF).toByte()
        buffer[1] = (msgLen and 0xFF).toByte()
        System.arraycopy(ndefRecord, 0, buffer, 2, msgLen)
        return writeStandardFileInCurrentApp(fileNo, buffer)
    }

    private fun writeStandardFileInCurrentApp(fileNo: Byte, data: ByteArray): Boolean {
        return try {
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false
            val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile ?: return false
            val fullData = ByteArray(fs.fileSize)
            System.arraycopy(data, 0, fullData, 0, minOf(fs.fileSize, data.size))
            val payload = PayloadBuilder().writeToStandardFile(fileNo.toInt(), fullData) ?: return false
            desfire.writeData(payload)
        } catch (e: Exception) {
            false
        }
    }

    private fun formatPiccInternal(): Boolean {
        return try {
            if (!desfire.selectApplication(MASTER_AID)) return false
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false
            desfire.formatPICC()
        } catch (e: Exception) {
            false
        }
    }

    private fun sendNative(ins: Byte, data: ByteArray = ByteArray(0)): ByteArray {
        val lc = data.size
        val apdu = ByteArray(5 + lc + 1)
        apdu[0] = 0x90.toByte()
        apdu[1] = ins
        apdu[4] = lc.toByte()
        if (lc > 0) System.arraycopy(data, 0, apdu, 5, lc)
        return transport.transceive(apdu)
    }

    companion object {
        private const val TAG = "NATOHelper"
        private val MASTER_AID: ByteArray   = byteArrayOf(0x00, 0x00, 0x00)
        private val NDEF_APP_AID: ByteArray = byteArrayOf(0x01, 0x00, 0x00)
        private const val FILE_CC: Byte    = 0x01
        private const val FILE_NPS: Byte   = 0x02
        private const val FILE_EXTRA: Byte = 0x03
        private const val CC_FILE_SIZE = 23
        private val DEFAULT_DES_KEY = ByteArray(8) { 0x00 }
        private const val KEYNO_MASTER: Byte = 0x00

        fun buildMimeNdefRecord(mimeType: String, payload: ByteArray): ByteArray {
            val typeBytes = mimeType.toByteArray(Charsets.US_ASCII)
            val typeLen = typeBytes.size
            val payloadLen = payload.size
            val sr = payloadLen < 256
            var header = 0x80 or 0x40 or (if (sr) 0x10 else 0) or 0x02
            return if (sr) {
                val result = ByteArray(3 + typeLen + payloadLen)
                result[0] = header.toByte()
                result[1] = typeLen.toByte()
                result[2] = payloadLen.toByte()
                System.arraycopy(typeBytes, 0, result, 3, typeLen)
                System.arraycopy(payload, 0, result, 3 + typeLen, payloadLen)
                result
            } else {
                val result = ByteArray(6 + typeLen + payloadLen)
                result[0] = header.toByte()
                result[1] = typeLen.toByte()
                result[2] = ((payloadLen shr 24) and 0xFF).toByte()
                result[3] = ((payloadLen shr 16) and 0xFF).toByte()
                result[4] = ((payloadLen shr 8) and 0xFF).toByte()
                result[5] = (payloadLen and 0xFF).toByte()
                System.arraycopy(typeBytes, 0, result, 6, typeLen)
                System.arraycopy(payload, 0, result, 6 + typeLen, payloadLen)
                result
            }
        }

        fun connect(tag: Tag, debug: Boolean = false): NATOHelper? {
            val transport = AndroidIsoDepTransport.connect(tag) ?: return null
            return connect(transport, debug)
        }

        fun connect(transport: ApduTransport, debug: Boolean = false): NATOHelper {
            val wrapper = ApduTransportIsoDepWrapper(transport)
            val adapter = DESFireAdapter(wrapper, debug)
            val desfire = DESFireEV1().apply {
                setAdapter(adapter)
            }
            return NATOHelper(transport, desfire)
        }

        fun formatPiccForNatoNdef(tag: Tag, debug: Boolean = false, seedNpsMimeType: String = "application/x.nps.v1-0", seedNpsPayload: ByteArray = """{"type":"nps-seed","msg":"Initial NATO NPS"}""".toByteArray(), npsCapacityBytes: Int = 2048, extraCapacityBytes: Int = 2048): Boolean {
            val helper = connect(tag, debug) ?: return false
            return try { helper.lowLevelFormatPiccForNatoNdef(seedNpsMimeType, seedNpsPayload, npsCapacityBytes, extraCapacityBytes) } finally { helper.close() }
        }

        fun formatPiccForNatoNdef(transport: ApduTransport, debug: Boolean = false, seedNpsMimeType: String = "application/x.nps.v1-0", seedNpsPayload: ByteArray = """{"type":"nps-seed","msg":"Initial NATO NPS"}""".toByteArray(), npsCapacityBytes: Int = 2048, extraCapacityBytes: Int = 2048): Boolean {
            val helper = connect(transport, debug)
            return try { helper.lowLevelFormatPiccForNatoNdef(seedNpsMimeType, seedNpsPayload, npsCapacityBytes, extraCapacityBytes) } finally { helper.close() }
        }
    }
}
