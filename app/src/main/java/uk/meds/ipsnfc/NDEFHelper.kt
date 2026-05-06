package uk.meds.ipsnfc

import android.nfc.Tag
import android.util.Log
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile
import nfcjlib.core.DESFireAdapter
import nfcjlib.core.DESFireEV1
import nfcjlib.core.KeyType
import kotlin.math.max
import kotlin.math.min

class NDEFHelper private constructor(
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

    fun readExtraPlain(): ByteArray? {
        return try {
            if (!desfire.selectApplication(IPS_AID)) {
                Log.w(TAG, "readExtraPlain: IPS app not present / not selectable")
                null
            } else {
                val fs = desfire.getFileSettings(FILE_EXTRA.toInt()) as? StandardDesfireFile
                    ?: run {
                        Log.e(TAG, "readExtraPlain: file $FILE_EXTRA not found or not Standard file")
                        return null
                    }

                val size = fs.fileSize
                Log.d(TAG, "readExtraPlain: file size=$size")

                val data = desfire.readData(FILE_EXTRA, 0, size)
                if (data == null) {
                    Log.e(TAG, "readExtraPlain: readData returned null (code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})")
                }
                data
            }
        } catch (e: Exception) {
            Log.e(TAG, "readExtraPlain failed", e)
            null
        }
    }

    /**
     * Read the "Dual Section" data:
     * 1) RO from Type 4 NDEF app (000001), file E104 (0x02)
     * 2) RW from private IPS app (665544), file 0x01
     */
    fun readDualSectionNdef(): Pair<ByteArray?, ByteArray?>? {
        return try {
            // 1) Read RO from Type 4 NDEF app
            var ro: ByteArray? = null
            if (desfire.selectApplication(NDEF_APP_AID)) {
                if (desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) {
                    val fs = desfire.getFileSettings(FILE_NDEF.toInt()) as? StandardDesfireFile
                    if (fs != null) {
                        val fileBytes = desfire.readData(FILE_NDEF, 0, fs.fileSize)
                        if (fileBytes != null && fileBytes.size > 2) {
                            val nlen = ((fileBytes[0].toInt() and 0xFF) shl 8) or (fileBytes[1].toInt() and 0xFF)
                            if (nlen > 0 && nlen + 2 <= fileBytes.size) {
                                // For now, we return the whole NDEF message bytes. 
                                // Higher level can parse the MIME record if needed.
                                // Actually, handleReadDualNdef in MainActivity extracts the payload.
                                ro = fileBytes.copyOfRange(2, 2 + nlen)
                            }
                        }
                    }
                }
            }

            // 2) Read RW from private IPS app
            val rw = readExtraPlain()

            Pair(ro, rw)
        } catch (e: Exception) {
            Log.e(TAG, "readDualSectionNdef failed", e)
            null
        }
    }

    fun writeDualSectionNdef(
        roMimeType: String,
        roPayload: ByteArray,
        rwMimeType: String,
        rwPayload: ByteArray
    ): Boolean {
        return try {
            val npsOk = writeType4NdefRo(roMimeType, roPayload)
            if (!npsOk) {
                Log.e(TAG, "writeDualSectionNdef: failed to write RO NPS into Type-4 NDEF file")
                return false
            }

            val extraNdef = buildMimeNdefRecord(rwMimeType, rwPayload)
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
                if (!created && desfire.code != 0xDE) {
                    Log.e(TAG, "NDEFHelper: failed to create IPS app code=${desfire.code.toString(16)}")
                    return false
                }
            }

            if (!desfire.selectApplication(IPS_AID)) {
                Log.e(TAG, "NDEFHelper: failed to select IPS AID")
                return false
            }

            val fileIds = runCatching { desfire.fileIds }.getOrElse { ByteArray(0) }
            val haveExtra = fileIds.any { it == FILE_EXTRA }

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

                val deleted = runCatching { desfire.deleteFile(FILE_EXTRA) }.getOrElse { false }
                if (!deleted) return false
            }

            val pb = PayloadBuilder()
            val extraPayload = pb.createStandardFile(
                FILE_EXTRA.toInt(),
                PayloadBuilder.CommunicationSetting.Plain,
                keyRW = KEYNO_RW.toInt(),
                keyCar = KEYNO_CAR.toInt(),
                keyR = 0xE,
                keyW = 0xE,
                fileSize = desired
            ) ?: throw RuntimeException("NDEFHelper: createStandardFile(EXTRA) returned null")

            val createdExtra = desfire.createStdDataFile(extraPayload)
            if (!createdExtra) {
                Log.e(TAG, "NDEFHelper: failed to create EXTRA file")
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "NDEFHelper: ensureIpsAppAndExtraFile failed", e)
            return false
        }
        return true
    }

    private fun writeStandardFileInternal(fileNo: Byte, data: ByteArray): Boolean {
        return try {
            if (!desfire.selectApplication(IPS_AID)) return false
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false

            val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile ?: return false
            val fileSize = fs.fileSize
            if (data.size > fileSize) return false

            val fullData = ByteArray(fileSize)
            System.arraycopy(data, 0, fullData, 0, data.size)

            val pb = PayloadBuilder()
            val payloadApdu = pb.writeToStandardFile(fileNo.toInt(), fullData)
                ?: throw RuntimeException("writeToStandardFile($fileNo) returned null")

            desfire.writeData(payloadApdu)
        } catch (e: Exception) {
            Log.e(TAG, "writeStandardFileInternal($fileNo) failed", e)
            false
        }
    }

    private fun writeType4NdefRo(
        mimeType: String,
        payload: ByteArray
    ): Boolean {
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) return false
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false

            val fs = desfire.getFileSettings(FILE_NDEF.toInt()) as? StandardDesfireFile ?: return false
            val capacity = fs.fileSize
            val ndefRecord = buildMimeNdefRecord(mimeType, payload)
            val msgLen = ndefRecord.size

            if (msgLen + 2 > capacity) return false

            val fileBytes = ByteArray(capacity) { 0 }
            fileBytes[0] = ((msgLen shr 8) and 0xFF).toByte()
            fileBytes[1] = (msgLen and 0xFF).toByte()
            System.arraycopy(ndefRecord, 0, fileBytes, 2, msgLen)

            writeStandardFileInCurrentApp(FILE_NDEF, fileBytes)
        } catch (e: Exception) {
            Log.e(TAG, "writeType4NdefRo failed", e)
            false
        }
    }

    private fun writeStandardFileInCurrentApp(fileNo: Byte, data: ByteArray): Boolean {
        return try {
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false
            val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile ?: return false

            val fileSize = fs.fileSize
            val fullData = ByteArray(fileSize)
            val len = min(fileSize, data.size)
            System.arraycopy(data, 0, fullData, 0, len)

            val pb = PayloadBuilder()
            val payload = pb.writeToStandardFile(fileNo.toInt(), fullData)
                ?: throw RuntimeException("writeToStandardFile($fileNo) returned null")

            desfire.writeData(payload)
        } catch (e: Exception) {
            Log.e(TAG, "writeStandardFileInCurrentApp($fileNo) failed", e)
            false
        }
    }

    private fun formatPiccInternal(): Boolean {
        return try {
            if (!desfire.selectApplication(MASTER_AID)) return false
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false
            desfire.formatPICC()
        } catch (e: Exception) {
            Log.e(TAG, "formatPiccInternal failed", e)
            false
        }
    }

    fun lowLevelFormatPiccForDualNdef(
        seedMimeType: String,
        seedPayload: ByteArray,
        ndefCapacityBytes: Int
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

            val ccFileSize = 15
            val ccSize0 = (ccFileSize and 0xFF).toByte()
            val ccSize1 = ((ccFileSize shr 8) and 0xFF).toByte()
            val ccSize2 = ((ccFileSize shr 16) and 0xFF).toByte()
            val createCCBody = byteArrayOf(
                0x01,
                0x03, 0xE1.toByte(),
                0x00,
                0xEE.toByte(), 0xEE.toByte(),
                ccSize0, ccSize1, ccSize2
            )
            val respCreateCC = sendNative(0xCD.toByte(), createCCBody)
            val swCreateCC = respCreateCC.last().toInt() and 0xFF
            if (swCreateCC != 0x00 && swCreateCC != 0xDE) return false

            val ndefSize = ndefCapacityBytes
            val ndefSize0 = (ndefSize and 0xFF).toByte()
            val ndefSize1 = ((ndefSize shr 8) and 0xFF).toByte()
            val ndefSize2 = ((ndefSize shr 16) and 0xFF).toByte()

            val createNdefFileBody = byteArrayOf(
                0x02,
                0x04, 0xE1.toByte(),
                0x00,
                0xEE.toByte(), 0x00,
                ndefSize0, ndefSize1, ndefSize2
            )
            val respCreateNdef = sendNative(0xCD.toByte(), createNdefFileBody)
            val swCreateNdef = respCreateNdef.last().toInt() and 0xFF
            if (swCreateNdef != 0x00 && swCreateNdef != 0xDE) return false

            val maxNdefLenHi = ((ndefCapacityBytes shr 8) and 0xFF).toByte()
            val maxNdefLenLo = (ndefCapacityBytes and 0xFF).toByte()

            val cc = ByteArray(ccFileSize) { 0 }
            cc[0]  = 0x00
            cc[1]  = 0x0f
            cc[2]  = 0x20
            cc[3]  = 0x00
            cc[4]  = 0x3B
            cc[5]  = 0x00
            cc[6]  = 0x34
            cc[7]  = 0x04
            cc[8]  = 0x06
            cc[9]  = 0xE1.toByte()
            cc[10] = 0x04
            cc[11] = maxNdefLenHi
            cc[12] = maxNdefLenLo
            cc[13] = 0x00
            cc[14] = 0xFF.toByte()

            if (!writeStandardFileInCurrentApp(0x01, cc)) return false

            val ndefRecord = buildMimeNdefRecord(seedMimeType, seedPayload)
            val ndefMsgLen = ndefRecord.size
            if (ndefMsgLen + 2 > ndefCapacityBytes) return false

            val ndefFileBytes = ByteArray(ndefCapacityBytes) { 0 }
            ndefFileBytes[0] = ((ndefMsgLen shr 8) and 0xFF).toByte()
            ndefFileBytes[1] = (ndefMsgLen and 0xFF).toByte()
            System.arraycopy(ndefRecord, 0, ndefFileBytes, 2, ndefMsgLen)

            if (!writeStandardFileInCurrentApp(0x02, ndefFileBytes)) return false

            true
        } catch (e: Exception) {
            Log.e(TAG, "lowLevelFormatPiccForDualNdef failed", e)
            false
        }
    }

    private fun sendNative(ins: Byte, data: ByteArray = ByteArray(0)): ByteArray {
        val lc = data.size
        val apdu = ByteArray(5 + lc + 1)
        var i = 0
        apdu[i++] = 0x90.toByte()
        apdu[i++] = ins
        apdu[i++] = 0x00
        apdu[i++] = 0x00
        apdu[i++] = lc.toByte()
        if (lc > 0) {
            System.arraycopy(data, 0, apdu, i, lc)
            i += lc
        }
        apdu[i] = 0x00

        return transport.transceive(apdu)
    }

    fun requiredType4Capacity(mimeType: String, payload: ByteArray): Int {
        val record = buildMimeNdefRecord(mimeType, payload)
        return 2 + record.size
    }

    fun chooseNdefCapacity(requiredBytes: Int): Int {
        val headroom = 128
        val minSize  = 512
        val align    = 32
        val base = max(minSize, requiredBytes + headroom)
        return ((base + (align - 1)) / align) * align
    }

    fun canWriteType4NdefRo(mimeType: String, payload: ByteArray): Boolean {
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) return false
            if (!desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)) return false

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

        private val IPS_AID: ByteArray = byteArrayOf(0x44, 0x55, 0x66)
        private val MASTER_AID: ByteArray = byteArrayOf(0x00, 0x00, 0x00)
        private val NDEF_APP_AID: ByteArray = byteArrayOf(0x01, 0x00, 0x00)

        private const val FILE_NDEF: Byte = 0x02
        private const val FILE_EXTRA: Byte = 0x01

        private val DEFAULT_DES_KEY = ByteArray(8) { 0x00 }

        private const val APPLICATION_MASTER_KEY_SETTINGS: Byte = 0x0F
        private const val APPLICATION_KEY_COUNT: Byte = 5

        private const val KEYNO_MASTER: Byte = 0x00
        private const val KEYNO_RW: Byte     = 0x01
        private const val KEYNO_CAR: Byte    = 0x02
        private const val KEYNO_R: Byte      = 0x03
        private const val KEYNO_W: Byte      = 0x04

        private const val MIN_EXTRA_FILE_SIZE = 256

        fun buildMimeNdefRecord(mimeType: String, payload: ByteArray): ByteArray {
            val typeBytes = mimeType.toByteArray(Charsets.US_ASCII)
            val typeLen = typeBytes.size
            val payloadLen = payload.size
            val isShort = payloadLen < 256
            val tnfMedia = 0x02

            var header = 0
            header = header or 0x80  // MB
            header = header or 0x40  // ME
            if (isShort) header = header or 0x10 // SR
            header = header or tnfMedia

            val headerByte = header.toByte()

            return if (isShort) {
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

        fun connect(tag: Tag, debug: Boolean = false): NDEFHelper? {
            val transport = AndroidIsoDepTransport.connect(tag) ?: return null
            return try {
                connect(transport, debug)
            } catch (e: Exception) {
                transport.close()
                null
            }
        }

        fun connect(transport: ApduTransport, debug: Boolean = false): NDEFHelper {
            val wrapper = ApduTransportIsoDepWrapper(transport)
            val adapter = DESFireAdapter(wrapper, debug)
            val desfire = DESFireEV1().apply {
                setAdapter(adapter)
            }
            return NDEFHelper(transport, desfire)
        }

        fun formatPiccForDualNdef(
            tag: Tag,
            debug: Boolean = false,
            seedMimeType: String = "application/x.nps.v1-0",
            seedPayload: ByteArray = """{"type":"seed","msg":"Initial NDEF"}""".toByteArray(),
            ndefCapacityBytes: Int = 2048
        ): Boolean {
            val helper = connect(tag, debug) ?: return false
            return try {
                helper.lowLevelFormatPiccForDualNdef(seedMimeType, seedPayload, ndefCapacityBytes)
            } finally {
                helper.close()
            }
        }
        
        fun formatPiccForDualNdef(
            transport: ApduTransport,
            debug: Boolean = false,
            seedMimeType: String = "application/x.nps.v1-0",
            seedPayload: ByteArray = """{"type":"seed","msg":"Initial NDEF"}""".toByteArray(),
            ndefCapacityBytes: Int = 2048
        ): Boolean {
            val helper = connect(transport, debug)
            return try {
                helper.lowLevelFormatPiccForDualNdef(seedMimeType, seedPayload, ndefCapacityBytes)
            } finally {
                helper.close()
            }
        }
    }
}