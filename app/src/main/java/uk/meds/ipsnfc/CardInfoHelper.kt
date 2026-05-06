package uk.meds.ipsnfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import androidx.appcompat.app.AlertDialog
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile
import nfcjlib.core.DESFireAdapter
import nfcjlib.core.DESFireEV1
import nfcjlib.core.KeyType
import java.util.Locale
import kotlin.math.min

object CardInfoHelper {

    private const val TAG = "CardInfoHelper"

    private val DEFAULT_DES_KEY = ByteArray(8) { 0x00 }
    private val MASTER_AID      = byteArrayOf(0x00, 0x00, 0x00)
    private val NDEF_APP_AID    = byteArrayOf(0x01, 0x00, 0x00) // 000001 (LSB first)
    private val IPS_AID         = byteArrayOf(0x44, 0x55, 0x66) // 665544 (LSB first)

    // In your layouts
    private const val FILE_CC: Byte    = 0x01 // E103 inside 000001
    private const val FILE_NDEF: Byte  = 0x02 // E104 inside 000001 (Dual RO or NATO NPS)
    private const val FILE_EXTRA: Byte = 0x03 // E105 inside 000001 (NATO extra)

    data class Report(
        val text: String
    )

    /**
     * Build a quick, detailed report. Non-destructive.
     */
    fun buildReport(tag: Tag, debug: Boolean = true): Report {
        val isoDep = IsoDep.get(tag) ?: return Report("IsoDep not supported (not a DESFire/Type4 tag).")

        return try {
            isoDep.timeout = 5000
            isoDep.connect()

            val isoDepWrapper = DefaultIsoDepWrapper(isoDep)
            val adapter = DESFireAdapter(isoDepWrapper, debug)

            val desfire = DESFireEV1().apply {
                setAdapter(adapter)
                setPrint(debug)
            }

            val sb = StringBuilder()

            // -----------------------------------------------------------------
            // NFC tech basics
            // -----------------------------------------------------------------
            sb.appendLine("=== NFC TECH ===")
            sb.appendLine("UID: ${tag.id.toHex()}")
            sb.appendLine("Techs: ${tag.techList.joinToString()}")
            sb.appendLine("IsoDep timeout: ${isoDep.timeout} ms")
            sb.appendLine("IsoDep maxTransceiveLength: ${isoDep.maxTransceiveLength}")
            sb.appendLine("IsoDep hiLayerResponse: ${isoDep.hiLayerResponse?.toHex() ?: "(null)"}")
            sb.appendLine("IsoDep historicalBytes: ${isoDep.historicalBytes?.toHex() ?: "(null)"}")
            sb.appendLine()

            // -----------------------------------------------------------------
            // DESFire version (nice sanity check)
            // -----------------------------------------------------------------
            sb.appendLine("=== DESFIRE VERSION ===")
            runCatching {
                val v = desfire.version
                if (v != null) {
                    sb.appendLine("HW: ${v.hardwareType} v${v.hardwareVersionMajor}.${v.hardwareVersionMinor}")
                    sb.appendLine("SW: ${v.softwareType} v${v.softwareVersionMajor}.${v.softwareVersionMinor}")
                } else {
                    sb.appendLine("(version unavailable)")
                }
            }.onFailure {
                sb.appendLine("(version read failed: ${it.message})")
            }
            sb.appendLine()

            // -----------------------------------------------------------------
            // List applications
            // -----------------------------------------------------------------
            sb.appendLine("=== APPLICATIONS ===")
            desfire.selectApplication(MASTER_AID)
            // auth is sometimes required for listing; attempt but don't fail hard
            runCatching { desfire.authenticate(DEFAULT_DES_KEY, 0x00.toByte(), KeyType.DES) }

            val appIds = runCatching { desfire.applicationsIds }.getOrNull()
            if (appIds == null || appIds.isEmpty()) {
                sb.appendLine("(no apps reported or failed to enumerate)")
            } else {
                val apps = appIds.map { it.id }.sortedWith(compareBy({ it.size }, { it.toHex() }))
                sb.appendLine("Count: ${apps.size}")
                apps.forEach { aid ->
                    sb.appendLine(" - AID: ${aid.toHex()} ${aidLabel(aid)}")
                }
            }
            sb.appendLine()

            // For our known apps, do deeper inspection in a predictable order
            val targets = listOf(
                NDEF_APP_AID to "000001 (NDEF / Type4)",
                IPS_AID to "665544 (IPS private app)"
            )

            for ((aid, label) in targets) {
                if (!desfire.selectApplication(aid)) {
                    sb.appendLine("=== APP $label ===")
                    sb.appendLine("(not present / not selectable)")
                    sb.appendLine()
                    continue
                }

                sb.appendLine("=== APP $label ===")

                // auth to app master to read settings + files (best effort)
                val authOk = runCatching { desfire.authenticate(DEFAULT_DES_KEY, 0x00.toByte(), KeyType.DES) }
                    .getOrDefault(false)
                sb.appendLine("Auth(master,key0,00..00): ${if (authOk) "OK" else "FAILED/NOT NEEDED"}")

                // list files
                val fileIds = runCatching { desfire.fileIds }.getOrElse { ByteArray(0) }
                if (fileIds.isEmpty()) {
                    sb.appendLine("Files: (none or failed to list)")
                    sb.appendLine()
                    continue
                }

                sb.appendLine("Files (${fileIds.size}): ${fileIds.joinToString { "0x%02X".format(it) }}")
                fileIds.sorted().forEach { fileNo ->
                    val fs = runCatching { desfire.getFileSettings((fileNo.toInt() and 0xFF)) }
                        .getOrNull() as? StandardDesfireFile

                    val size = fs?.fileSize ?: -1
                    sb.append(" - file 0x%02X".format(fileNo))
                    if (size >= 0) sb.append(" size=${size}B")
                    else sb.append(" size=(unknown)")

                    // MIME if we can detect
                    val mime = runCatching {
                        val bytes = readWholeFile(desfire, fileNo, size)
                        detectMimeForKnownLayouts(aid, fileNo, bytes)
                    }.getOrNull()

                    if (!mime.isNullOrBlank()) sb.append(" mime=$mime")
                    sb.appendLine()
                }

                // If 000001: hex dump file 1 (CC / E103)
                if (aid.contentEquals(NDEF_APP_AID)) {
                    sb.appendLine()
                    sb.appendLine("--- CC (file 0x01 / E103) hex dump ---")
                    val ccFs = runCatching { desfire.getFileSettings(FILE_CC.toInt()) }.getOrNull() as? StandardDesfireFile
                    val ccSize = ccFs?.fileSize ?: 32
                    val ccBytes = runCatching { readWholeFile(desfire, FILE_CC, ccSize) }.getOrElse { ByteArray(0) }

                    if (ccBytes.isEmpty()) {
                        sb.appendLine("(CC read failed or empty)")
                    } else {
                        sb.appendLine(hexDump(ccBytes, maxBytes = min(ccBytes.size, 128)))
                    }
                }

                sb.appendLine()
            }

            Report(sb.toString())
        } catch (e: Exception) {
            Report("CardInfo failed: ${e.message}")
        } finally {
            try { isoDep.close() } catch (_: Exception) {}
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun aidLabel(aid: ByteArray): String = when {
        aid.contentEquals(NDEF_APP_AID) -> "(Type4 NDEF)"
        aid.contentEquals(IPS_AID) -> "(IPS private)"
        else -> ""
    }

    private fun readWholeFile(desfire: DESFireEV1, fileNo: Byte, knownSize: Int): ByteArray {
        val size = if (knownSize > 0) knownSize else {
            val fs = desfire.getFileSettings(fileNo.toInt()) as? StandardDesfireFile
            fs?.fileSize ?: 0
        }
        if (size <= 0) return ByteArray(0)
        return desfire.readData(fileNo, 0, size) ?: ByteArray(0)
    }

    /**
     * Detect MIME type for:
     * - 000001 file 0x02 / 0x03 (Type4: NLEN
     * - 665544 file 0x01 (NDEF record bytes stored directly, no NLEN)
     * Everything else -> null
     */
    private fun detectMimeForKnownLayouts(aid: ByteArray, fileNo: Byte, fileBytes: ByteArray): String? {
        if (fileBytes.isEmpty()) return null

        return when {
            // 000001: NDEF files (E104/E105)
            aid.contentEquals(NDEF_APP_AID) && (fileNo == FILE_NDEF || fileNo == FILE_EXTRA) -> {
                parseType4NdefMimeType(fileBytes)
            }
            // 665544: your "extra" file stores raw NDEF record bytes (no NLEN)
            aid.contentEquals(IPS_AID) && fileNo == 0x01.toByte() -> {
                parseRawNdefRecordMimeType(fileBytes)
            }
            // Everything else: no MIME in your DES-only test layout (raw bytes)
            else -> null
        }
    }

    /**
     * Type4 NDEF file: [0..1] NLEN (BE), then NDEF message.
     * We assume a single record and return its MIME type if TNF=media-type.
     */
    private fun parseType4NdefMimeType(fileBytes: ByteArray): String? {
        if (fileBytes.size < 3) return null
        val nlen = ((fileBytes[0].toInt() and 0xFF) shl 8) or (fileBytes[1].toInt() and 0xFF)
        if (nlen <= 0 || 2 + nlen > fileBytes.size) return null
        val ndef = fileBytes.copyOfRange(2, 2 + nlen)
        return parseRawNdefRecordMimeType(ndef)
    }

    /**
     * Raw NDEF record parsing (single record):
     * returns mime type if TNF==0x02 (media-type).
     *
     * Supports SR=1 and SR=0; ignores ID field (IL assumed 0 in our encoders).
     */
    private fun parseRawNdefRecordMimeType(ndefBytes: ByteArray): String? {
        if (ndefBytes.size < 4) return null

        var idx = 0
        val header = ndefBytes[idx++].toInt() and 0xFF
        val sr = (header and 0x10) != 0
        val il = (header and 0x08) != 0
        val tnf = header and 0x07

        val typeLen = ndefBytes[idx++].toInt() and 0xFF

        val payloadLen = if (sr) {
            ndefBytes[idx++].toInt() and 0xFF
        } else {
            if (idx + 4 > ndefBytes.size) return null
            ((ndefBytes[idx].toInt() and 0xFF) shl 24) or
                    ((ndefBytes[idx + 1].toInt() and 0xFF) shl 16) or
                    ((ndefBytes[idx + 2].toInt() and 0xFF) shl 8) or
                    (ndefBytes[idx + 3].toInt() and 0xFF)
                        .also { idx += 4 }
        }

        val idLen = if (il) (ndefBytes[idx++].toInt() and 0xFF) else 0

        if (idx + typeLen > ndefBytes.size) return null
        val type = ndefBytes.copyOfRange(idx, idx + typeLen)
        idx += typeLen

        if (idLen > 0) {
            if (idx + idLen > ndefBytes.size) return null
            idx += idLen
        }

        // We only need the MIME type (type field) when TNF=media-type
        if (tnf != 0x02) return null

        return runCatching { String(type, Charsets.US_ASCII) }.getOrNull()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }

    private fun hexDump(bytes: ByteArray, maxBytes: Int = bytes.size): String {
        val n = min(bytes.size, maxBytes)
        val sb = StringBuilder()
        var offset = 0
        while (offset < n) {
            val lineLen = min(16, n - offset)
            sb.append(String.format(Locale.US, "%04X  ", offset))
            for (i in 0 until 16) {
                if (i < lineLen) sb.append(String.format("%02X ", bytes[offset + i]))
                else sb.append("   ")
            }
            sb.append(" ")
            for (i in 0 until lineLen) {
                val b = bytes[offset + i].toInt() and 0xFF
                sb.append(if (b in 32..126) b.toChar() else '.')
            }
            sb.appendLine()
            offset += lineLen
        }
        return sb.toString()
    }
}
