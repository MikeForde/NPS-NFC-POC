package uk.meds.ipsnfc

import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper
import java.io.IOException

class ApduTransportIsoDepWrapper(
    private val transport: ApduTransport
) : IsoDepWrapper {

    @Throws(IOException::class)
    override fun transceive(data: ByteArray): ByteArray {
        return try {
            transport.transceive(data)
        } catch (e: IOException) {
            throw e
        } catch (e: Exception) {
            throw IOException("APDU transceive failed via ${transport.name}", e)
        }
    }
}