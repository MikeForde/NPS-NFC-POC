package uk.meds.ipsnfc

interface ApduTransport {
    val name: String

    @Throws(Exception::class)
    fun transceive(command: ByteArray): ByteArray

    fun close()
}