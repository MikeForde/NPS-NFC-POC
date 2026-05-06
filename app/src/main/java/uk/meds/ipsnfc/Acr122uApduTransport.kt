package uk.meds.ipsnfc

import com.acs.smartcard.Reader

class Acr122uApduTransport(
    private val reader: Reader,
    private val slotNum: Int
) : ApduTransport {

    override val name: String = "ACR122U slot $slotNum"

    @Synchronized
    override fun transceive(command: ByteArray): ByteArray {
        val response = ByteArray(4096)

        val responseLength = reader.transmit(
            slotNum,
            command,
            command.size,
            response,
            response.size
        )

        return response.copyOf(responseLength)
    }

    override fun close() {
        // The owning Acr122uReader closes the physical USB reader.
        // Leave this as a no-op for now to avoid powering down between helper calls.
    }
}