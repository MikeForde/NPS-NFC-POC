package uk.meds.ipsnfc

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.util.Log

class Acr122uUsbController(
    private val context: Context,
    private val onStatus: (String) -> Unit,
    private val onReaderReady: (UsbDevice) -> Unit
) {
    private val usbManager =
        context.getSystemService(Context.USB_SERVICE) as UsbManager

    private var registered = false

    private val permissionReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.action != ACTION_USB_PERMISSION) return

            @Suppress("DEPRECATION")
            val device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE) as? UsbDevice

            val granted = intent.getBooleanExtra(
                UsbManager.EXTRA_PERMISSION_GRANTED,
                false
            )

            if (device == null) {
                onStatus("USB permission response received, but no device found")
                return
            }

            if (granted) {
                onStatus("USB permission granted for ${device.productName ?: "ACR122U"}")
                onReaderReady(device)
            } else {
                onStatus("USB permission denied")
            }
        }
    }

    fun start() {
        registerReceiverIfNeeded()

        val reader = findAcr122u()

        if (reader == null) {
            onStatus("ACR122U not found")
            return
        }

        onStatus(
            "Found USB reader: " +
                    Integer.toHexString(reader.vendorId).padStart(4, '0') +
                    ":" +
                    Integer.toHexString(reader.productId).padStart(4, '0') +
                    " " +
                    (reader.productName ?: "")
        )

        if (usbManager.hasPermission(reader)) {
            onStatus("USB permission already granted")
            onReaderReady(reader)
        } else {
            requestPermission(reader)
        }
    }

    fun stop() {
        if (registered) {
            try {
                context.unregisterReceiver(permissionReceiver)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "Receiver was not registered", e)
            }
            registered = false
        }
    }

    private fun registerReceiverIfNeeded() {
        if (registered) return

        val filter = IntentFilter(ACTION_USB_PERMISSION)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(
                permissionReceiver,
                filter,
                Context.RECEIVER_NOT_EXPORTED
            )
        } else {
            @Suppress("DEPRECATION")
            context.registerReceiver(permissionReceiver, filter)
        }

        registered = true
    }

    private fun findAcr122u(): UsbDevice? {
        val devices = usbManager.deviceList

        for (device in devices.values) {
            if (
                device.vendorId == ACS_VENDOR_ID &&
                device.productId == ACR122U_PRODUCT_ID
            ) {
                return device
            }
        }

        return null
    }

    private fun requestPermission(device: UsbDevice) {
        val flags =
            PendingIntent.FLAG_UPDATE_CURRENT or
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        PendingIntent.FLAG_MUTABLE
                    } else {
                        0
                    }

        val permissionIntent = PendingIntent.getBroadcast(
            context,
            0,
            Intent(ACTION_USB_PERMISSION).setPackage(context.packageName),
            flags
        )

        onStatus("Requesting USB permission")
        usbManager.requestPermission(device, permissionIntent)
    }

    companion object {
        private const val TAG = "Acr122uUsbController"

        private const val ACTION_USB_PERMISSION =
            "uk.meds.ipsnfc.USB_PERMISSION"

        private const val ACS_VENDOR_ID = 0x072f
        private const val ACR122U_PRODUCT_ID = 0x2200
    }
}