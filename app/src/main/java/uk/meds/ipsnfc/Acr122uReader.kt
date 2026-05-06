package uk.meds.ipsnfc

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.util.Log
import com.acs.smartcard.Reader

class Acr122uReader(
    private val usbManager: UsbManager,
    private val onStatus: (String) -> Unit,
    private val onUid: (String) -> Unit,
    private val onCardPresent: (ApduTransport, String) -> Unit
) {
    private var reader: Reader? = null
    private var currentDevice: UsbDevice? = null

    @Volatile
    private var activeSlot: Int? = null

    @Volatile
    private var cardBusy: Boolean = false

    fun open(device: UsbDevice) {
        close()

        try {
            val r = Reader(usbManager)
            reader = r
            currentDevice = device

            r.setOnStateChangeListener { slotNum, prevState, currState ->
                Log.d(TAG, "Slot $slotNum state changed: $prevState -> $currState")

                if (currState == Reader.CARD_PRESENT) {
                    if (cardBusy) {
                        Log.d(TAG, "Ignoring CARD_PRESENT while busy")
                        return@setOnStateChangeListener
                    }

                    activeSlot = slotNum
                    cardBusy = true

                    onStatus("ACR122U: card present")

                    try {
                        readUid(slotNum)
                    } finally {
                        cardBusy = false
                    }

                } else if (currState == Reader.CARD_ABSENT) {
                    activeSlot = null
                    cardBusy = false
                    onStatus("ACR122U: card removed")
                }
            }

            r.open(device)

            onStatus(
                "ACR122U opened: " +
                        "${device.productName ?: "reader"} " +
                        "slots=${r.numSlots}"
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to open ACR122U", e)
            onStatus("ACR122U open failed: ${e.message}")
            close()
        }
    }

    private fun transceive(slotNum: Int, command: ByteArray): ByteArray {
        val r = reader ?: throw IllegalStateException("ACR122U reader not open")

        val response = ByteArray(4096)

        val responseLength = r.transmit(
            slotNum,
            command,
            command.size,
            response,
            response.size
        )

        return response.copyOf(responseLength)
    }

    private fun readUid(slotNum: Int) {
        val r = reader ?: run {
            onStatus("ACR122U: reader not open")
            return
        }

        try {
            /*
             * Power up / activate the contactless card.
             * For ACR122U the contactless/PICC interface is normally slot 0.
             */
            val atr = r.power(slotNum, Reader.CARD_WARM_RESET)
            Log.d(TAG, "ATR: ${atr.toHex()}")

            val protocol = r.setProtocol(
                slotNum,
                Reader.PROTOCOL_T0 or Reader.PROTOCOL_T1
            )
            Log.d(TAG, "Protocol: $protocol")

            /*
             * ACR122U Get UID APDU:
             * FF CA 00 00 00
             *
             * Successful response should be:
             * UID bytes + 90 00
             */
            val command = byteArrayOf(
                0xFF.toByte(),
                0xCA.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte()
            )

            val actual = transceive(slotNum, command)

            Log.d(TAG, "UID APDU response: ${actual.toHex()}")

            if (actual.size >= 2 &&
                actual[actual.size - 2] == 0x90.toByte() &&
                actual[actual.size - 1] == 0x00.toByte()
            ) {
                val uid = actual.copyOfRange(0, actual.size - 2).toHex(":")
                onUid(uid)
                onStatus("ACR122U UID: $uid")
                val transport = Acr122uApduTransport(r, slotNum)
                onCardPresent(transport, uid)
            } else {
                onStatus("ACR122U UID read failed: ${actual.toHex()}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "UID read failed", e)
            onStatus("ACR122U UID read error: ${e.message}")
        }
    }

    fun close() {
        try {
            reader?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing ACR122U", e)
        } finally {
            reader = null
            currentDevice = null
        }
    }

    private fun ByteArray.toHex(separator: String = " "): String {
        return joinToString(separator) { b ->
            "%02X".format(b.toInt() and 0xFF)
        }
    }

    companion object {
        private const val TAG = "Acr122uReader"
    }
}