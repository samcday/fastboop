package dev.dioxus.main;

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import org.json.JSONArray
import org.json.JSONObject

// need to re-export buildconfig down from the parent
import win.fastboop.mobile.BuildConfig;
typealias BuildConfig = BuildConfig;

class MainActivity : WryActivity() {
    private val usbPermissionAction = "win.fastboop.mobile.USB_PERMISSION"
    private val usbConnections = mutableMapOf<String, UsbDeviceConnection>()

    @Volatile
    private var lastPermissionResult: String? = null

    private val usbManager: UsbManager
        get() = getSystemService(Context.USB_SERVICE) as UsbManager

    private val usbPermissionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != usbPermissionAction) {
                return
            }

            val device = usbDeviceFrom(intent)
            val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
            lastPermissionResult = "${device?.deviceName ?: "unknown"}:$granted"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val filter = IntentFilter(usbPermissionAction)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbPermissionReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(usbPermissionReceiver, filter)
        }
    }

    override fun onDestroy() {
        unregisterReceiver(usbPermissionReceiver)
        synchronized(usbConnections) {
            usbConnections.values.forEach { it.close() }
            usbConnections.clear()
        }
        super.onDestroy()
    }

    fun fastboopUsbSnapshot(): String {
        val devices = JSONArray()
        usbManager.deviceList.entries
            .sortedBy { it.key }
            .forEach { entry ->
                val device = entry.value
                devices.put(
                    JSONObject()
                        .put("name", entry.key)
                        .put("vendorId", device.vendorId)
                        .put("productId", device.productId)
                        .put("deviceClass", device.deviceClass)
                        .put("deviceSubclass", device.deviceSubclass)
                        .put("deviceProtocol", device.deviceProtocol)
                        .put("interfaceCount", device.interfaceCount)
                        .put("hasPermission", usbManager.hasPermission(device))
                )
            }

        return JSONObject()
            .put("devices", devices)
            .put("lastPermissionResult", lastPermissionResult ?: JSONObject.NULL)
            .toString()
    }

    fun fastboopRequestUsbPermission(deviceName: String): Boolean {
        val device = usbManager.deviceList[deviceName] ?: return false
        if (usbManager.hasPermission(device)) {
            lastPermissionResult = "$deviceName:true"
            return true
        }

        val request = {
            usbManager.requestPermission(device, usbPermissionIntent())
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && mainLooper.isCurrentThread) {
            request()
        } else {
            runOnUiThread { request() }
        }
        return true
    }

    fun fastboopOpenUsbDevice(deviceName: String): Int {
        val device = usbManager.deviceList[deviceName] ?: return -1
        if (!usbManager.hasPermission(device)) {
            return -2
        }

        val connection = usbManager.openDevice(device) ?: return -3
        synchronized(usbConnections) {
            usbConnections.remove(deviceName)?.close()
            usbConnections[deviceName] = connection
        }
        return connection.fileDescriptor
    }

    fun fastboopCloseUsbDevice(deviceName: String): Boolean {
        synchronized(usbConnections) {
            val connection = usbConnections.remove(deviceName) ?: return false
            connection.close()
            return true
        }
    }

    private fun usbPermissionIntent(): PendingIntent {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                PendingIntent.FLAG_MUTABLE
            } else {
                0
            }
        val intent = Intent(usbPermissionAction).setPackage(packageName)
        return PendingIntent.getBroadcast(this, 0, intent, flags)
    }

    @Suppress("DEPRECATION")
    private fun usbDeviceFrom(intent: Intent): UsbDevice? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
        } else {
            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
        }
    }
}
