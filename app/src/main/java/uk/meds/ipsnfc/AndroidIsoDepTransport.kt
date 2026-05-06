package uk.meds.ipsnfc

import android.nfc.Tag
import android.nfc.tech.IsoDep

class AndroidIsoDepTransport private constructor(
    private val isoDep: IsoDep
) : ApduTransport {

    override val name: String = "Android IsoDep"

    override fun transceive(command: ByteArray): ByteArray {
        return isoDep.transceive(command)
    }

    override fun close() {
        try {
            isoDep.close()
        } catch (_: Exception) {
        }
    }

    companion object {
        fun connect(tag: Tag, timeoutMs: Int = 5000): AndroidIsoDepTransport? {
            val isoDep = IsoDep.get(tag) ?: return null

            return try {
                isoDep.connect()
                isoDep.timeout = timeoutMs
                AndroidIsoDepTransport(isoDep)
            } catch (_: Exception) {
                try {
                    isoDep.close()
                } catch (_: Exception) {
                }
                null
            }
        }
    }
}