package uk.meds.ipsnfc

/**
 * Kotlin port of your Java PayloadBuilder.
 * Generates payloads for DESFire EV1 WRITE_DATA / CREATE_STD_DATA_FILE commands.
 */
class PayloadBuilder {

    // keep the same semantics as the Java version
    private val MAXIMUM_FILE_NUMBER = 14   // used only for sanity checks
    private val MAXIMUM_KEY_NUMBER = 15
    private val MAXIMUM_FILE_SIZE = 256    // not enforced in createStandardFile, but we respect it in our code

    enum class CommunicationSetting {
        Plain, MACed, Encrypted
    }

    /**
     * Build payload for command 0xCD (Create Std Data File)
     */
    fun createStandardFile(
        fileNumber: Int,
        communicationSetting: CommunicationSetting,
        keyRW: Int,
        keyCar: Int,
        keyR: Int,
        keyW: Int,
        fileSize: Int
    ): ByteArray? {
        // sanity checks (same as Java)
        if (fileNumber < 0 || fileNumber > MAXIMUM_FILE_NUMBER) return null
        if (keyRW < 0 || keyRW > MAXIMUM_KEY_NUMBER) return null
        if (keyCar < 0 || keyCar > MAXIMUM_KEY_NUMBER) return null
        if (keyR < 0 || keyR > MAXIMUM_KEY_NUMBER) return null
        if (keyW < 0 || keyW > MAXIMUM_KEY_NUMBER) return null
        if (fileSize < 1) return null

        // communication settings
        val communicationSettings: Byte = when (communicationSetting) {
            CommunicationSetting.Plain      -> 0x00
            CommunicationSetting.MACed      -> 0x01
            CommunicationSetting.Encrypted  -> 0x03
        }.toByte()

        // access rights
        val accessRightsRwCar: Byte = ((keyRW shl 4) or (keyCar and 0x0F)).toByte()
        val accessRightsRW: Byte = ((keyR shl 4) or (keyW and 0x0F)).toByte()

        val fileSizeByte = intTo3ByteArrayLsb(fileSize)

        val payload = ByteArray(7)
        payload[0] = (fileNumber and 0xFF).toByte()
        payload[1] = communicationSettings
        payload[2] = accessRightsRwCar
        payload[3] = accessRightsRW
        System.arraycopy(fileSizeByte, 0, payload, 4, 3)
        return payload
    }

    /**
     * Build payload for 0x3D (Write Data) with offset 0 and full length.
     */
    fun writeToStandardFile(fileNumber: Int, data: ByteArray?): ByteArray? {
        // sanity checks
        if (fileNumber < 0 || fileNumber > MAXIMUM_FILE_NUMBER) return null
        if (data == null) return null

        // offset 0
        val offset = byteArrayOf(0x00, 0x00, 0x00)
        val lengthOfData = intTo3ByteArrayLsb(data.size)

        val payload = ByteArray(7 + data.size)
        payload[0] = (fileNumber and 0xFF).toByte()
        System.arraycopy(offset, 0, payload, 1, 3)
        System.arraycopy(lengthOfData, 0, payload, 4, 3)
        System.arraycopy(data, 0, payload, 7, data.size)

        return payload
    }

    // int -> 3-byte LSB array
    private fun intTo3ByteArrayLsb(value: Int): ByteArray {
        return byteArrayOf(
            (value and 0xFF).toByte(),
            ((value shr 8) and 0xFF).toByte(),
            ((value shr 16) and 0xFF).toByte()
        )
    }
}
