package uk.meds.ipsnfc  // <-- make sure this matches your package name

import android.nfc.NfcAdapter
import android.nfc.Tag
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import android.nfc.tech.Ndef
import android.util.Log
import android.view.View
import android.widget.AdapterView
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.lifecycle.lifecycleScope
import android.widget.ArrayAdapter
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TabHost
import androidx.appcompat.app.AlertDialog
import android.content.Context
import android.hardware.usb.UsbManager


class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var acr122uController: Acr122uUsbController? = null
    private var acr122uReader: Acr122uReader? = null

    // Authoritative in-app payloads (NOT the textboxes)
    private var roBytes: ByteArray = ByteArray(0)
    private var rwBytes: ByteArray = ByteArray(0)

    private val MIME_NPS_GZ  = "application/x.nps.gzip.v1-0"
    private val MIME_EXT_GZ  = "application/x.ext.gzip.v1-0"

    // Optional: remember whether each blob is currently gzipped (binary)
    private var roIsGzip: Boolean = false
    private var rwIsGzip: Boolean = false

    private enum class PendingAction { NONE, WRITE, READ, FORMAT, WRITE_DUAL_NDEF, FORMAT_FOR_NDEF, READ_DUAL_NDEF, WRITE_NATO, READ_NATO, FORMAT_NATO, CARD_INFO }

    private var nfcAdapter: NfcAdapter? = null
    private var pendingAction: PendingAction = PendingAction.NONE

    private val http = OkHttpClient()
    private val httpClient = okhttp3.OkHttpClient()
    private val gson = com.google.gson.GsonBuilder().setPrettyPrinting().create()

    private data class IpsListItem(
        val packageUUID: String,
        val given: String,
        val name: String
    ) {
        fun label(): String = "${name}, ${given}  (${packageUUID.take(8)})"
    }

    private data class SplitResponse(
        val id: String?,
        val cutoff: String?,
        val protect: String?,
        val ro: Any?,
        val rw: Any?
    )

    private var ipsList: List<IpsListItem> = emptyList()
    private var selectedPackageUuid: String? = null

    private val PREFS = "ips_prefs"
    private val KEY_BASE_URL = "ips_base_url"

    private val BASE_LOCAL = "http://localhost:5049"
    private val BASE_AZURE = "https://ipsmern-dep.azurewebsites.net"

    private val KEY_POC_AUTO_DECOMPRESS = "poc_auto_decompress_rw"

    private fun getPocAutoDecompress(): Boolean {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getBoolean(KEY_POC_AUTO_DECOMPRESS, true) // default ON
    }

    private fun setPocAutoDecompress(enabled: Boolean) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putBoolean(KEY_POC_AUTO_DECOMPRESS, enabled).apply()
    }

    private val KEY_SPLIT_MODE = "ips_split_mode"
    private val SPLIT_MODE_UNIFIED = 0
    private val SPLIT_MODE_POC = 1

    private fun getSplitMode(): Int {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getInt(KEY_SPLIT_MODE, SPLIT_MODE_UNIFIED)
    }

    private fun setSplitMode(mode: Int) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putInt(KEY_SPLIT_MODE, mode).apply()
    }

    private fun getIpsBase(): String {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getString(KEY_BASE_URL, BASE_AZURE) ?: BASE_AZURE
    }

    private fun setIpsBase(base: String) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putString(KEY_BASE_URL, base).apply()
    }

    private fun ipsListUrl(): String = "${getIpsBase()}/ips/list"

    private val KEY_PROTECT_LEVEL = "ips_protect_level"

    private val PROTECT_NONE = 0
    private val PROTECT_JWE  = 1
    private val PROTECT_OMIT = 2

    private fun getProtectLevel(): Int {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getInt(KEY_PROTECT_LEVEL, PROTECT_NONE)
    }

    private fun ipsSplitUrl(packageUuid: String): String {
        val protect = getProtectLevel()
        val base = getIpsBase()

        return when (getSplitMode()) {
            SPLIT_MODE_POC ->
                "$base/ipsdatasplitpoc/$packageUuid?protect=$protect"
            else ->
                "$base/ipsunifiedsplit/$packageUuid?protect=$protect"
        }
    }

    private fun setProtectLevel(level: Int) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putInt(KEY_PROTECT_LEVEL, level).apply()
    }


    private lateinit var statusText: TextView
    private lateinit var textHistoric: EditText
    private lateinit var textRw: EditText
    private lateinit var buttonWrite: Button
    private lateinit var buttonRead: Button
    private lateinit var buttonFormatApp: Button
    private lateinit var buttonWriteDualNdef: Button
    private lateinit var buttonFormatForNDEF:Button
    private lateinit var buttonReadDual:Button
    private lateinit var buttonWriteNato:Button
    private lateinit var buttonReadNato:Button
    private lateinit var buttonFormatForNATO:Button
    private lateinit var tabHost: TabHost
    private lateinit var tabRoLabel: TextView
    private lateinit var tabRoSize: TextView
    private lateinit var tabRwLabel: TextView
    private lateinit var tabRwSize: TextView
    private lateinit var buttonCardInfo: Button




    // For now, dummy payloads. Later these will be gzip’d IPS historic/new data.
    private val dummyHistoricPayload: ByteArray
        get() = """
            {
              "type": "historic",
              "message": "Dummy historic IPS payload 2",
              "entries": [ "Problem A", "Allergy B" ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)

    private val dummyRwPayload: ByteArray
        get() = """
            {
              "type": "rw",
              "message": "Dummy read/write IPS payload 2",
              "entries": [ "Recent BP", "New medication" ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)

    override fun onDestroy() {
        acr122uReader?.close()
        acr122uController?.stop()
        super.onDestroy()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<ImageButton>(R.id.buttonSettings).setOnClickListener {
            showSettingsDialog()
        }

        tabHost = findViewById(android.R.id.tabhost)
        tabHost.setup()

        val (roInd, roRefs) = makeTabIndicator("DATA 1 (RO)")
        tabRoLabel = roRefs.first
        tabRoSize  = roRefs.second

        val (rwInd, rwRefs) = makeTabIndicator("DATA 2 (RW)")
        tabRwLabel = rwRefs.first
        tabRwSize  = rwRefs.second

        tabHost.addTab(
            tabHost.newTabSpec("ro")
                .setIndicator(roInd)
                .setContent(R.id.tab_ro)
        )

        tabHost.addTab(
            tabHost.newTabSpec("rw")
                .setIndicator(rwInd)
                .setContent(R.id.tab_rw)
        )

        tabHost.currentTab = 0


        statusText = findViewById(R.id.statusText)
        textHistoric = findViewById(R.id.textHistoric)
        textRw = findViewById(R.id.textRw)
        buttonWrite = findViewById(R.id.buttonWrite)
        buttonRead = findViewById(R.id.buttonRead)
        buttonFormatApp = findViewById(R.id.buttonFormatApp)
        buttonWriteDualNdef = findViewById(R.id.buttonWriteDualNdef)
        //buttonFormatForNDEF = findViewById(R.id.buttonFormatForNDEF)
        buttonReadDual = findViewById(R.id.buttonReadDual)
        buttonWriteNato = findViewById(R.id.buttonWriteNato)
        buttonReadNato = findViewById(R.id.buttonReadNato)
        //buttonFormatForNATO = findViewById(R.id.buttonFormatForNATO)
        buttonCardInfo = findViewById(R.id.buttonCardInfo)
        val spinner = findViewById<Spinner>(R.id.spinnerIps)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            Toast.makeText(this, "NFC not available on this device", Toast.LENGTH_LONG).show()
            statusText.text = "NFC not available on this device"
        }

        buttonWrite.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.WRITE
            statusText.text = "WRITE mode: Tap DESFire card"
        }

        buttonRead.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.READ
            statusText.text = "READ mode: Tap DESFire card"
        }

        buttonFormatApp.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.FORMAT
            statusText.text = "FORMAT mode: Tap DESFire card – this will erase ALL apps"
        }

        buttonWriteDualNdef.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.WRITE_DUAL_NDEF
            statusText.text = "WRITE NDEF dual mode: tap DESFire card\n(This will FORMAT and recreate the app/files)"
        }

//        buttonFormatForNDEF.setOnClickListener {
//            if (nfcAdapter == null) return@setOnClickListener
//            pendingAction = PendingAction.FORMAT_FOR_NDEF
//            statusText.text = "FORMAT For NDEF dual mode: tap DESFire card\n(This will FORMAT for NDEF + DES)"
//        }

        buttonReadDual.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.READ_DUAL_NDEF
            statusText.text = "READ NDEF dual mode: tap DESFire card\n(This will READ NDEF + DES)"
        }

        buttonWriteNato.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.WRITE_NATO
            statusText.text = "WRITE NATO mode: tap DESFire card\n(This will WRITE NATO NDEF)"
        }

        buttonReadNato.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.READ_NATO
            statusText.text = "READ NATO mode: tap DESFire card\n(This will READ NATO NDEF)"
        }

//        buttonFormatForNATO.setOnClickListener {
//            if (nfcAdapter == null) return@setOnClickListener
//            pendingAction = PendingAction.FORMAT_NATO
//            statusText.text = "FORMAT for NATO mode: tap DESFire card\n(This will FORMAT for NATO NDEF)"
//        }

        buttonCardInfo.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.CARD_INFO
            statusText.text = "Card info mode: tap NFC card"
        }

        textHistoric.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) { updateTabSizes() }
        })

        textRw.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) { updateTabSizes() }
        })


        spinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>,
                view: android.view.View,
                position: Int,
                id: Long
            ) {
                val uuid = ipsList.getOrNull(position)?.packageUUID
                selectedPackageUuid = uuid

                uuid?.let {
                    // Optional: update status immediately
                    statusText.text = "Fetching IPS split for: $it"
                    fetchAndShowSplit(it)   // <-- implement / call your existing network fetch here
                }
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>) {
                selectedPackageUuid = null
            }
        }

        fun enableInnerScrolling(editText: EditText) {
            editText.setOnTouchListener { v, event ->
                if (v.hasFocus()) {
                    v.parent.requestDisallowInterceptTouchEvent(true)

                    if (event.action == android.view.MotionEvent.ACTION_UP) {
                        v.parent.requestDisallowInterceptTouchEvent(false)
                    }
                }
                false
            }
        }


        findViewById<Button>(R.id.buttonRefreshIps).setOnClickListener {
            refreshIpsList()
        }

        enableInnerScrolling(textHistoric)
        enableInnerScrolling(textRw)
        updateTabSizes()

        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager

        acr122uReader = Acr122uReader(
            usbManager = usbManager,
            onStatus = { message ->
                runOnUiThread {
                    Log.d("ACR122U", message)
                    statusText.text = message
                }
            },
            onUid = { uid ->
                runOnUiThread {
                    Log.d("ACR122U", "UID from external reader: $uid")
                    statusText.text = "External ACR122U UID:\n$uid"
                }
            },
            onCardPresent = { transport, uid ->
                handleTransportDiscovered(
                    transport = transport,
                    sourceLabel = "External ACR122U",
                    uid = uid
                )
            }
        )

        acr122uController = Acr122uUsbController(
            context = this,
            onStatus = { message ->
                runOnUiThread {
                    Log.d("ACR122U", message)
                    statusText.text = message
                }
            },
            onReaderReady = { device ->
                runOnUiThread {
                    Log.d("ACR122U", "Reader ready: ${device.deviceName}")
                    statusText.text = "ACR122U ready: ${device.productName ?: device.deviceName}"
                }

                acr122uReader?.open(device)
            }
        )

        acr122uController?.start()


// load once at startup
        refreshIpsList()
    }

    override fun onResume() {
        super.onResume()
        enableReaderMode()
    }

    override fun onPause() {
        super.onPause()
        disableReaderMode()
    }

    private fun handleTransportDiscovered(
        transport: ApduTransport,
        sourceLabel: String,
        uid: String? = null
    ) {
        val currentAction = pendingAction

        if (currentAction == PendingAction.NONE) {
            runOnUiThread {
                statusText.text = buildString {
                    append("$sourceLabel card detected")
                    if (uid != null) append("\nUID: $uid")
                }
            }
            return
        }

        if (currentAction == PendingAction.CARD_INFO) {
            try {
                val helper = DesfireHelper.connect(transport, debug = true)
                val versionSummary = helper.getVersionSummary() ?: "Version: unavailable"
                val cardUid = helper.getUidHex() ?: uid ?: "UID unavailable"

                runOnUiThread {
                    statusText.text = "$sourceLabel card info\nUID: $cardUid\n$versionSummary"
                    pendingAction = PendingAction.NONE
                }

                helper.close()
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "$sourceLabel card info error: ${e.message}"
                    pendingAction = PendingAction.NONE
                }
                transport.close()
            }
            return
        }

        val helper = try {
            DesfireHelper.connect(transport, debug = true)
        } catch (e: Exception) {
            runOnUiThread {
                statusText.text = "$sourceLabel DESFire connect failed: ${e.message}"
                pendingAction = PendingAction.NONE
            }
            transport.close()
            return
        }

        try {
            when (currentAction) {
                PendingAction.WRITE -> handleWrite(helper)
                PendingAction.READ -> handleRead(helper)
                PendingAction.FORMAT -> handleFormat(helper)

                else -> {
                    runOnUiThread {
                        statusText.text =
                            "$sourceLabel mode not yet transport-enabled: $currentAction"
                        pendingAction = PendingAction.NONE
                    }
                }
            }
        } catch (e: Exception) {
            runOnUiThread {
                statusText.text = "$sourceLabel error: ${e.message}"
                pendingAction = PendingAction.NONE
            }
        } finally {
            helper.close()
        }
    }

    private fun enableReaderMode() {
        val options = Bundle().apply {
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250)
        }

        nfcAdapter?.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A or
                    NfcAdapter.FLAG_READER_NFC_B or   // harmless, but covers Type 4B too
                    NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
            options
        )
    }

    private fun decodeBase64(s: String): ByteArray {
        return android.util.Base64.decode(s, android.util.Base64.DEFAULT)
    }

    private fun isGzip(bytes: ByteArray): Boolean {
        return bytes.size >= 2 && bytes[0] == 0x1F.toByte() && bytes[1] == 0x8B.toByte()
    }

    private fun looksLikeBase64(s: String): Boolean {
        val t = s.trim()
        if (t.length < 8) return false
        // base64 charset + optional newlines
        return t.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' || it == '\n' || it == '\r' }
    }

    private fun gzip(bytes: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        java.util.zip.GZIPOutputStream(out).use { it.write(bytes) }
        return out.toByteArray()
    }

    // Convert bytes -> what we show in the textbox
// If autoDecompress is ON and it's gz, show decompressed pretty JSON if possible.
// If OFF and it's gz, show base64 to illustrate compactness.
    private fun bytesToUiString(bytes: ByteArray, autoDecompress: Boolean): String {
        if (bytes.isEmpty()) return ""

        return if (isGzip(bytes)) {
            if (!autoDecompress) {
                // compact view: base64 of gzip bytes
                android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
            } else {
                val raw = gunzip(bytes)
                val s = raw.toString(Charsets.UTF_8)
                // try pretty JSON; if not JSON, just return as-is
                runCatching {
                    val parsed = gson.fromJson(s, Any::class.java)
                    gson.toJson(parsed)
                }.getOrDefault(s)
            }
        } else {
            // plain UTF-8
            val s = bytes.toString(Charsets.UTF_8)
            runCatching {
                val parsed = gson.fromJson(s, Any::class.java)
                gson.toJson(parsed)
            }.getOrDefault(s)
        }
    }


    private fun gunzip(bytes: ByteArray): ByteArray {
        java.util.zip.GZIPInputStream(bytes.inputStream()).use { gis ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (true) {
                val n = gis.read(buf)
                if (n <= 0) break
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }

    private fun makeTabIndicator(title: String): Pair<View, Pair<TextView, TextView>> {
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 8, 16, 8)
            setBackgroundResource(R.drawable.tab_indicator_bg)
            isClickable = true
            isFocusable = true
        }

        val t1 = TextView(this).apply {
            text = title
            textSize = 14f
            setSingleLine(true)
        }

        val t2 = TextView(this).apply {
            text = "0 B"
            textSize = 11f
            alpha = 0.8f
            setSingleLine(true)
        }

        wrap.addView(t1)
        wrap.addView(t2)
        return wrap to (t1 to t2)
    }

    private fun formatBytes(n: Int): String {
        if (n < 1024) return "$n B"
        val kb = n / 1024.0
        return String.format("%.1f KB", kb, n)
    }

//    private fun editTextByteSize(et: EditText): Int {
//        // count bytes as actually written to NFC / sent over network (UTF-8)
//        return et.text?.toString()?.toByteArray(Charsets.UTF_8)?.size ?: 0
//    }

    private fun gunzippedSize(bytes: ByteArray?): Int {
        if (bytes == null) return 0
        return try {
            gunzip(bytes).size
        } catch (_: Exception) {
            0
        }
    }

    private fun looksLikeGzip(bytes: ByteArray?): Boolean {
        return bytes != null &&
                bytes.size >= 2 &&
                bytes[0] == 0x1F.toByte() &&
                bytes[1] == 0x8B.toByte()
    }

    // Always return gzip-binary bytes for writing (never base64 text)
    private fun ensureGzipBytesForWrite(
        preferredGzip: ByteArray?,
        editText: EditText,
        fallbackJson: String
    ): ByteArray {
        // 1) If we already have canonical gzip bytes, use them.
        if (preferredGzip != null && preferredGzip.isNotEmpty() && looksLikeGzip(preferredGzip)) {
            return preferredGzip
        }

        // 2) Otherwise treat the UI as plaintext JSON/text and gzip it.
        val s = editText.text?.toString().orEmpty().ifBlank { fallbackJson }
        return gzip(s.toByteArray(Charsets.UTF_8))
    }


    private fun formatZippedAndUnzipped(zipped: Int, unzipped: Int): String {
        return when {
            zipped > 0 && unzipped > 0 ->
                "Z: ${formatBytes(zipped)}  U: ${formatBytes(unzipped)}"
            zipped > 0 ->
                "Z: ${formatBytes(zipped)}"
            unzipped > 0 ->
                "U: ${formatBytes(unzipped)}"
            else ->
                "0 B"
        }
    }


    private fun updateTabSizes() {
        // --- RO ---
        val roZipped = roGzipBytes?.size ?: 0
        val roUnzipped =
            if (roIsPlaintext) {
                roPlainText?.toByteArray(Charsets.UTF_8)?.size ?: 0
            } else {
                gunzippedSize(roGzipBytes)
            }

        // --- RW ---
        val rwZipped = rwGzipBytes?.size ?: 0
        val rwUnzipped = gunzippedSize(rwGzipBytes)

        tabRoSize.text = formatZippedAndUnzipped(roZipped, roUnzipped)
        tabRwSize.text = formatZippedAndUnzipped(rwZipped, rwUnzipped)
    }


    private fun refreshTextViewsFromBytes() {
        val autoDecompress = getPocAutoDecompress()

        textHistoric.setText(bytesToUiString(roBytes, autoDecompress))
        textRw.setText(bytesToUiString(rwBytes, autoDecompress))

        roIsGzip = isGzip(roBytes)
        rwIsGzip = isGzip(rwBytes)

        updateTabSizes()
    }

    private fun disableReaderMode() {
        nfcAdapter?.disableReaderMode(this)
    }

    /**
     * Called on a binder thread when a tag is discovered.
     */
    override fun onTagDiscovered(tag: Tag?) {
        if (tag == null) return

        val techs = tag.techList.joinToString()
        runOnUiThread {
            statusText.text = "Tag techs: $techs"
        }

        val currentAction = pendingAction
        if (currentAction == PendingAction.NONE) return

        /*
         * Shared APDU transport path.
         *
         * These modes now use:
         *
         * Built-in NFC Tag
         *   -> AndroidIsoDepTransport
         *   -> handleTransportDiscovered(...)
         *   -> DesfireHelper.connect(transport)
         *
         * This mirrors the ACR122U path:
         *
         * ACR122U
         *   -> Acr122uApduTransport
         *   -> handleTransportDiscovered(...)
         *   -> DesfireHelper.connect(transport)
         */
        val canUseSharedTransport =
            currentAction == PendingAction.CARD_INFO ||
                    currentAction == PendingAction.WRITE ||
                    currentAction == PendingAction.READ ||
                    currentAction == PendingAction.FORMAT

        if (canUseSharedTransport) {
            val transport = AndroidIsoDepTransport.connect(tag)

            if (transport == null) {
                runOnUiThread {
                    Toast.makeText(
                        this,
                        "Tag is not DESFire / IsoDep connect failed",
                        Toast.LENGTH_SHORT
                    ).show()
                    statusText.text = "Built-in NFC: IsoDep connect failed"
                }
                return
            }

            val uid = tag.id?.joinToString(":") {
                "%02X".format(it.toInt() and 0xFF)
            }

            handleTransportDiscovered(
                transport = transport,
                sourceLabel = "Built-in NFC",
                uid = uid
            )

            return
        }

        /*
         * Built-in NFC only for now.
         *
         * These still depend on Android Tag / Ndef.get(tag) / helper.connect(tag).
         * We will refactor NDEFHelper and NATOHelper next.
         */
        if (currentAction == PendingAction.CARD_INFO) {
            try {
                handleCardInfo(tag)
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "Card info error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.WRITE_DUAL_NDEF) {
            try {
                handleWriteDualNdef(tag)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.FORMAT_FOR_NDEF) {
            try {
                handleFormatForDualNdef(tag)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.READ_DUAL_NDEF) {
            handleReadDualNdef(tag)
            return
        }

        if (currentAction == PendingAction.WRITE_NATO) {
            try {
                handleWriteNato(tag)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.READ_NATO) {
            try {
                handleReadNato(tag)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.FORMAT_NATO) {
            try {
                handleFormatForNato(tag)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        runOnUiThread {
            statusText.text = "Unhandled NFC action: $currentAction"
        }
    }

    private fun showSettingsDialog() {
        val baseOptions = arrayOf(
            "Local (http://localhost:5049)",
            "Azure (https://ipsmern-dep.azurewebsites.net)"
        )
        val protectOptions = arrayOf(
            "0 — No protection",
            "1 — Encrypt identifiers (JWE)",
            "2 — Omit identifiers"
        )

        val splitOptions = arrayOf(
            "Unified split (RO/RW JSON via /ipsunifiedsplit)",
            "POC split (RO plaintext + RW gzipped unified JSON via /ipsdatasplitpoc)"
        )

        var selectedSplit = getSplitMode().coerceIn(0, 1)

        var selectedAutoDecompress = getPocAutoDecompress()


        var selectedBaseIndex = when (getIpsBase()) {
            BASE_AZURE -> 1
            else -> 0
        }
        var selectedProtect = getProtectLevel().coerceIn(0, 2)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 0)
        }

        val baseLabel = TextView(this).apply { text = "API base URL"; textSize = 16f }
        content.addView(baseLabel)

        val baseGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            baseOptions.forEachIndexed { idx, label ->
                addView(RadioButton(this@MainActivity).apply {
                    text = label
                    id = 1000 + idx
                    isChecked = idx == selectedBaseIndex
                })
            }
            setOnCheckedChangeListener { _, checkedId ->
                selectedBaseIndex = checkedId - 1000
            }
        }
        content.addView(baseGroup)

        val spacer = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 24
            )
        }
        content.addView(spacer)

        val protectLabel = TextView(this).apply { text = "Protect level"; textSize = 16f }
        content.addView(protectLabel)

        val protectGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            protectOptions.forEachIndexed { idx, label ->
                addView(RadioButton(this@MainActivity).apply {
                    text = label
                    id = 2000 + idx
                    isChecked = idx == selectedProtect
                })
            }
            setOnCheckedChangeListener { _, checkedId ->
                selectedProtect = checkedId - 2000
            }
        }
        content.addView(protectGroup)

        val spacer2 = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 24
            )
        }
        content.addView(spacer2)

        val splitLabel = TextView(this).apply { text = "Split mode"; textSize = 16f }
        content.addView(splitLabel)

        val splitGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            splitOptions.forEachIndexed { idx, label ->
                addView(RadioButton(this@MainActivity).apply {
                    text = label
                    id = 3000 + idx
                    isChecked = idx == selectedSplit
                })
            }
            setOnCheckedChangeListener { _, checkedId ->
                selectedSplit = checkedId - 3000
            }
        }
        content.addView(splitGroup)

        val spacer3 = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 24
            )
        }
        content.addView(spacer3)

        val cb = android.widget.CheckBox(this).apply {
            text = "Auto Decompress/Unzip"
            isChecked = selectedAutoDecompress
            setOnCheckedChangeListener { _, checked ->
                selectedAutoDecompress = checked
            }
        }
        content.addView(cb)


        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Settings")
            .setView(content)
            .setPositiveButton("Save") { _, _ ->

                val previousBase = getIpsBase()
                val chosenBase = if (selectedBaseIndex == 1) BASE_AZURE else BASE_LOCAL

                val baseChanged = (chosenBase != previousBase)

                setIpsBase(chosenBase)
                setProtectLevel(selectedProtect)
                setSplitMode(selectedSplit)
                setPocAutoDecompress(selectedAutoDecompress)

                statusText.text =
                    "API: $chosenBase | protect=$selectedProtect | mode=$selectedSplit | unzip=$selectedAutoDecompress"

                if (baseChanged) {
                    // New server → list likely differs
                    refreshIpsList()
                } else {
                    // Same server → just re-fetch current patient with new protect/mode settings
                    selectedPackageUuid?.let { fetchAndShowSplit(it) }
                        ?: run { refreshIpsList() } // fallback if nothing selected yet
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

//    private fun capturePlaintextEditsIntoBytes() {
//        // Only treat textbox as authoritative when we are not gzipped
//        // AND the textbox doesn't look like a base64 display string.
//        val roText = textHistoric.text.toString()
//        if (!roIsGzip && !looksLikeBase64(roText)) {
//            roBytes = roText.toByteArray(Charsets.UTF_8)
//        }
//
//        val rwText = textRw.text.toString()
//        if (!rwIsGzip && !looksLikeBase64(rwText)) {
//            rwBytes = rwText.toByteArray(Charsets.UTF_8)
//        }
//
//        updateTabSizes()
//    }
private val nfcExec = java.util.concurrent.Executors.newSingleThreadExecutor()
    @Volatile private var nfcBusy = false

    private fun handleCardInfo(tag: Tag) {
        if (nfcBusy) return
        nfcBusy = true

        // Important: use tag.id + techList now if you want; but heavy IsoDep work in background.
        runOnUiThread { statusText.text = "Reading card info..." }

        nfcExec.execute {
            try {
                val report = CardInfoHelper.buildReport(tag, debug = true).text
                runOnUiThread { showCardInfoDialog(report) }
            } catch (e: Exception) {
                runOnUiThread { statusText.text = "Card info error: ${e.message}" }
            } finally {
                nfcBusy = false
                pendingAction = PendingAction.NONE
            }
        }
    }

    private fun showCardInfoDialog(report: String) {
        val tv = TextView(this).apply {
            text = report
            setPadding(32, 24, 32, 24)
            setTextIsSelectable(true)
            typeface = android.graphics.Typeface.MONOSPACE
        }
        val scroll = android.widget.ScrollView(this).apply { addView(tv) }

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Card Info")
            .setView(scroll)
            .setPositiveButton("Close", null)
            .show()
        logLong("Card Info Report", report)
        statusText.text = "Card info OK"
    }


    private fun logLong(tag: String, msg: String) {
        val chunk = 3500  // keep under Logcat ~4k limit
        var i = 0
        while (i < msg.length) {
            val end = (i + chunk).coerceAtMost(msg.length)
            android.util.Log.d(tag, msg.substring(i, end))
            i = end
        }
    }

    // --- NEW: store the "real" payloads separately from the EditTexts ---
// Universal internal representation: gzip binary for both, unless RO is plaintext POC.
    private var roIsPlaintext: Boolean = true
    private var roPlainText: String? = null
    private var roGzipBytes: ByteArray? = null

    private var rwGzipBytes: ByteArray? = null

    private fun fetchAndShowSplit(packageUUID: String) {
        runOnUiThread {
            statusText.text = "Fetching IPS split for $packageUUID..."
            pendingAction = PendingAction.NONE
        }

        val url = ipsSplitUrl(packageUUID)

        val req = Request.Builder()
            .url(url)
            .get()
            .build()

        httpClient.newCall(req).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                runOnUiThread { statusText.text = "Fetch failed: ${e.message}" }
            }

            override fun onResponse(call: okhttp3.Call, resp: okhttp3.Response) {
                resp.use {
                    if (!it.isSuccessful) {
                        runOnUiThread { statusText.text = "Fetch failed: HTTP ${it.code}" }
                        return
                    }

                    val body = it.body?.string().orEmpty()

                    try {
                        val mode = getSplitMode()
                        val autoDecompress = getPocAutoDecompress() // toggle reused for both modes
                        val root = org.json.JSONObject(body)

                        // reset stored payloads
                        roIsPlaintext = false
                        roPlainText = null
                        roGzipBytes = null
                        rwGzipBytes = null

                        var uiRoText = ""
                        var uiRwText = ""

                        var roBytesGz = -1
                        var rwBytesGz = -1
                        var roBytesJson = -1
                        var rwBytesJson = -1

                        if (mode == SPLIT_MODE_POC) {
                            // Expected POC shape:
                            // ro: { text: "...." }   (plaintext)
                            // rw: { bytesBase64: "...." }  (gzip binary encoded as base64)
                            val roObj = root.optJSONObject("ro")
                            val rwObj = root.optJSONObject("rw")

                            val roText = roObj?.optString("text", "") ?: ""
                            roIsPlaintext = true
                            roPlainText = roText

                            val rwB64 = rwObj?.optString("bytesBase64", "") ?: ""

                            // Store RW as gzip binary
                            if (rwB64.isNotBlank()) {
                                rwGzipBytes = decodeBase64(rwB64)
                                rwBytesGz = rwGzipBytes?.size ?: -1
                            }

                            // UI
                            uiRoText = roText

                            uiRwText = when {
                                rwGzipBytes == null -> ""
                                !autoDecompress -> {
                                    // show base64 (compact string) for illustration
                                    android.util.Base64.encodeToString(rwGzipBytes, android.util.Base64.NO_WRAP)
                                }
                                else -> {
                                    val jsonBytes = gunzip(rwGzipBytes!!)
                                    rwBytesJson = jsonBytes.size
                                    val jsonStr = jsonBytes.toString(Charsets.UTF_8)

                                    // pretty print JSON if possible; otherwise show raw text
                                    try {
                                        val parsed = gson.fromJson(jsonStr, Any::class.java)
                                        gson.toJson(parsed)
                                    } catch (_: Exception) {
                                        jsonStr
                                    }
                                }
                            }

                        } else {
                            // Unified split new shape (gzip+base64 default):
                            // {
                            //   encoding:"gzip+base64",
                            //   roGzB64:"...",
                            //   rwGzB64:"...",
                            //   roBytesJson:..., rwBytesJson:..., roBytesGz:..., rwBytesGz:...
                            // }
                            val encoding = root.optString("encoding", "json")

                            if (encoding.equals("gzip+base64", ignoreCase = true)) {
                                val roB64 = root.optString("roGzB64", "")
                                val rwB64 = root.optString("rwGzB64", "")

                                roBytesJson = root.optInt("roBytesJson", -1)
                                rwBytesJson = root.optInt("rwBytesJson", -1)
                                roBytesGz   = root.optInt("roBytesGz", -1)
                                rwBytesGz   = root.optInt("rwBytesGz", -1)

                                // Store BOTH as gzip binary
                                if (roB64.isNotBlank()) roGzipBytes = decodeBase64(roB64)
                                if (rwB64.isNotBlank()) rwGzipBytes = decodeBase64(rwB64)

                                // prefer actual sizes from bytes if server didn't provide
                                if (roBytesGz < 0) roBytesGz = roGzipBytes?.size ?: -1
                                if (rwBytesGz < 0) rwBytesGz = rwGzipBytes?.size ?: -1

                                // UI for RO
                                uiRoText = when {
                                    roGzipBytes == null -> ""
                                    !autoDecompress -> android.util.Base64.encodeToString(roGzipBytes, android.util.Base64.NO_WRAP)
                                    else -> {
                                        val jsonBytes = gunzip(roGzipBytes!!)
                                        if (roBytesJson < 0) roBytesJson = jsonBytes.size
                                        val jsonStr = jsonBytes.toString(Charsets.UTF_8)
                                        try {
                                            val parsed = gson.fromJson(jsonStr, Any::class.java)
                                            gson.toJson(parsed)
                                        } catch (_: Exception) {
                                            jsonStr
                                        }
                                    }
                                }

                                // UI for RW
                                uiRwText = when {
                                    rwGzipBytes == null -> ""
                                    !autoDecompress -> android.util.Base64.encodeToString(rwGzipBytes, android.util.Base64.NO_WRAP)
                                    else -> {
                                        val jsonBytes = gunzip(rwGzipBytes!!)
                                        if (rwBytesJson < 0) rwBytesJson = jsonBytes.size
                                        val jsonStr = jsonBytes.toString(Charsets.UTF_8)
                                        try {
                                            val parsed = gson.fromJson(jsonStr, Any::class.java)
                                            gson.toJson(parsed)
                                        } catch (_: Exception) {
                                            jsonStr
                                        }
                                    }
                                }

                            } else {
                                // Old JSON shape: { ro: {...}, rw: {...} }
                                // Keep old behaviour for now (and also stash plaintext in RO/RW edit boxes).
                                val split = gson.fromJson(body, SplitResponse::class.java)
                                val roPretty = gson.toJson(split.ro)
                                val rwPretty = gson.toJson(split.rw)

                                roIsPlaintext = true
                                roPlainText = roPretty
                                // (No gzip bytes in this legacy response)
                                roGzipBytes = null
                                rwGzipBytes = null

                                uiRoText = roPretty
                                uiRwText = rwPretty
                            }
                        }

                        roBytes = when {
                            roGzipBytes != null -> roGzipBytes!!
                            roIsPlaintext       -> (roPlainText ?: "").toByteArray(Charsets.UTF_8)
                            else                -> ByteArray(0)
                        }

                        rwBytes = when {
                            rwGzipBytes != null -> rwGzipBytes!!
                            else                -> ByteArray(0)
                        }

                        roIsGzip = looksLikeGzip(roBytes)
                        rwIsGzip = looksLikeGzip(rwBytes)

                        runOnUiThread {
                            textHistoric.setText(uiRoText)
                            textRw.setText(uiRwText)
                            updateTabSizes()

                            statusText.text = when (mode) {
                                SPLIT_MODE_POC -> {
                                    if (autoDecompress) {
                                        "Loaded POC split for $packageUUID (RW decompressed) gz=${rwBytesGz}B"
                                    } else {
                                        "Loaded POC split for $packageUUID (RW compact base64) gz=${rwBytesGz}B"
                                    }
                                }
                                else -> {
                                    if (roGzipBytes != null || rwGzipBytes != null) {
                                        if (autoDecompress) {
                                            "Loaded unified split for $packageUUID (decompressed) " +
                                                    "RO: ${roBytesGz}→${roBytesJson} bytes, RW: ${rwBytesGz}→${rwBytesJson} bytes"
                                        } else {
                                            "Loaded unified split for $packageUUID (compact base64) " +
                                                    "RO gz=${roBytesGz}B, RW gz=${rwBytesGz}B"
                                        }
                                    } else {
                                        "Loaded unified split for $packageUUID"
                                    }
                                }
                            }
                        }

                    } catch (ex: Exception) {
                        runOnUiThread { statusText.text = "Parse failed: ${ex.message}" }
                    }
                }
            }
        })
    }





    private fun refreshIpsList() {
        statusText.text = "Loading IPS list…"

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    val req = Request.Builder().url(ipsListUrl()).build()
                    http.newCall(req).execute().use { resp ->
                        if (!resp.isSuccessful) {
                            return@withContext Result.failure(Exception("HTTP ${resp.code}"))
                        }
                        val body = resp.body?.string() ?: "[]"
                        val arr = JSONArray(body)

                        val items = mutableListOf<IpsListItem>()
                        for (i in 0 until arr.length()) {
                            val o = arr.getJSONObject(i)
                            items.add(
                                IpsListItem(
                                    packageUUID = o.optString("packageUUID", ""),
                                    given = o.optString("given", ""),
                                    name = o.optString("name", "")
                                )
                            )
                        }
                        Result.success(items.toList())
                    }
                } catch (e: Exception) {
                    Result.failure(e)
                }
            }

            runOnUiThread {
                result.fold(
                    onSuccess = { items ->
                        ipsList = items
                        val spinner = findViewById<Spinner>(R.id.spinnerIps)
                        val labels = items.map { it.label() }.ifEmpty { listOf("(no records)") }

                        spinner.adapter = ArrayAdapter(
                            this@MainActivity,
                            android.R.layout.simple_spinner_dropdown_item,
                            labels
                        )

                        // Default selection
                        selectedPackageUuid = items.firstOrNull()?.packageUUID
                        statusText.text = "IPS list loaded (${items.size})"
                    },
                    onFailure = { e ->
                        statusText.text = "Failed to load IPS list: ${e.message}"
                    }
                )
            }
        }
    }


    private fun handleFormatForNato(tag: Tag) {
        // Use whatever is in the Historic box as the seed NPS payload,
        // or fall back to a sensible default if blank.
        val npsSeed =  """{"type":"nps-seed","msg":"Initial NATO NPS"}"""
            .toByteArray()

        val ok = NATOHelper.formatPiccForNatoNdef(
            tag = tag,
            debug = true,
            seedNpsMimeType = "application/x.nps.v1-0",
            seedNpsPayload = npsSeed,
            npsCapacityBytes = 2048,
            extraCapacityBytes = 2048
        )

        runOnUiThread {
            statusText.text = if (ok) "NATO format OK" else "NATO format FAILED"
            pendingAction = PendingAction.NONE
        }
    }


    private fun handleWriteNato(tag: Tag) {
        val helper = NATOHelper.connect(tag, debug = true) ?: run {
            runOnUiThread { statusText.text = "NATO write: connect failed" }
            return
        }

        try {
            val isPoc = (getSplitMode() == SPLIT_MODE_POC)

            // --- NPS / RO ---
            val npsMime: String
            val npsPayload: ByteArray

            if (isPoc) {
                // POC rule: RO is plaintext as typed/shown
                val roText = textHistoric.text?.toString().orEmpty()
                    .ifBlank { """{"type":"nps","msg":"NPS default"}""" }

                npsMime = "application/x.nps.v1-0"
                npsPayload = roText.toByteArray(Charsets.UTF_8)

                // Keep vars consistent (plaintext)
                roBytes = npsPayload
                roGzipBytes = null
                roIsGzip = false
                roIsPlaintext = true
                roPlainText = roText
            } else {
                // Unified rule: RO always gzip-binary
                npsMime = MIME_NPS_GZ
                npsPayload = ensureGzipBytesForWrite(
                    preferredGzip = roGzipBytes,
                    editText = textHistoric,
                    fallbackJson = """{"type":"nps","msg":"NPS default"}"""
                )

                roBytes = npsPayload
                roGzipBytes = npsPayload
                roIsGzip = true
                roIsPlaintext = false
                roPlainText = null
            }

            // --- EXTRA / RW (same for both modes: gzip-binary) ---
            val extraPayload = ensureGzipBytesForWrite(
                preferredGzip = rwGzipBytes,
                editText = textRw,
                fallbackJson = """{"type":"rw","msg":"Default extra"}"""
            )

            val ok = helper.writeNatoPayloads(
                npsMimeType = npsMime,
                npsPayload = npsPayload,
                extraMimeType = MIME_EXT_GZ,
                extraPayload = extraPayload
            )

            // Keep RW vars consistent (gzip)
            rwBytes = extraPayload
            rwGzipBytes = extraPayload
            rwIsGzip = true

            runOnUiThread {
                refreshTextViewsFromBytes()
                statusText.text = if (ok) "NATO write OK" else "NATO write FAILED"
                pendingAction = PendingAction.NONE
                updateTabSizes()
            }
        } finally {
            helper.close()
        }
    }




    private fun handleReadNato(tag: Tag) {
        val helper = NATOHelper.connect(tag, debug = true) ?: run {
            runOnUiThread { statusText.text = "NATO read: connect failed" }
            return
        }

        try {
            val payload = helper.readNatoPayloads()
            runOnUiThread {
                if (payload == null) {
                    statusText.text = "NATO read FAILED or not NATO layout"
                } else {
                    // ✅ Old variables (used by refreshTextViewsFromBytes)
                    roBytes = payload.npsPayload
                    rwBytes = payload.extraPayload

                    // ✅ New/canonical variables (used by updateTabSizes)
                    // NATO: treat as gzip binary if it looks gzip, otherwise treat as plaintext
                    val roIsGz = looksLikeGzip(payload.npsPayload)
                    if (roIsGz) {
                        roGzipBytes = payload.npsPayload
                        roPlainText = null
                        roIsPlaintext = false
                    } else {
                        roGzipBytes = null
                        roPlainText = payload.npsPayload.toString(Charsets.UTF_8)
                        roIsPlaintext = true
                    }

                    // RW: in your new model, RW is binary gzip (or at least we treat it that way)
                    rwGzipBytes = payload.extraPayload

                    // Refresh UI from the *old* byte variables (keeps existing behaviour)
                    refreshTextViewsFromBytes()

                    statusText.text = "NATO read OK"
                }

                updateTabSizes()
                pendingAction = PendingAction.NONE
            }
        } finally {
            helper.close()
        }
    }




    private fun handleReadDualNdef(tag: Tag) {
        val errors = mutableListOf<String>()

        var roRead: ByteArray? = null
        var rwRead: ByteArray? = null

        // 1) RO via Android NDEF
        val ndef = Ndef.get(tag)
        if (ndef != null) {
            try {
                ndef.connect()
                val msg = ndef.cachedNdefMessage ?: ndef.ndefMessage
                if (msg != null && msg.records.isNotEmpty()) {
                    val rec = msg.records[0]

                    // NOTE: For MIME records, rec.payload is the raw payload bytes (no encoding header).
                    // We treat it as "either plaintext UTF-8" or "gzip binary".
                    roRead = rec.payload
                } else {
                    errors += "No NDEF records on card"
                }
            } catch (e: Exception) {
                errors += "NDEF read failed: ${e.message}"
            } finally {
                try { ndef.close() } catch (_: Exception) {}
            }
        } else {
            errors += "Tag is not exposed as NDEF"
        }

        // 2) RW via DESFire file
        val helper = NDEFHelper.connect(tag, debug = true)
        if (helper != null) {
            try {
                val bytes = helper.readExtraPlain()
                if (bytes != null) {
                    // Trim trailing zero padding from fixed-size DESFire file
                    rwRead = bytes.dropLastWhile { it == 0.toByte() }.toByteArray()
                } else {
                    errors += "DESFire extra read returned null"
                }
            } catch (e: Exception) {
                errors += "DESFire extra read failed: ${e.message}"
            } finally {
                helper.close()
            }
        } else {
            errors += "DESFire connect failed for extra section"
        }

        runOnUiThread {
            // ✅ Old variables (used by refreshTextViewsFromBytes)
            roRead?.let { roBytes = it }
            rwRead?.let { rwBytes = it }

            // ✅ New/canonical variables (used by updateTabSizes)
            roRead?.let { bytes ->
                if (looksLikeGzip(bytes)) {
                    roGzipBytes = bytes
                    roPlainText = null
                    roIsPlaintext = false
                } else {
                    roGzipBytes = null
                    roPlainText = bytes.toString(Charsets.UTF_8)
                    roIsPlaintext = true
                }
            }

            rwRead?.let { bytes ->
                // In Dual, RW is *intended* to be gzip binary, but we allow plaintext too.
                if (looksLikeGzip(bytes)) {
                    rwGzipBytes = bytes
                } else {
                    rwGzipBytes = null
                }
            }

            refreshTextViewsFromBytes()

            statusText.text = buildString {
                append("READ Dual (NDEF + DESFire): ")
                append(if (errors.isEmpty()) "OK" else "partial/failed")
                if (errors.isNotEmpty()) {
                    append("\n")
                    append(errors.joinToString("\n"))
                }
            }

            updateTabSizes()
            pendingAction = PendingAction.NONE
        }
    }




    private fun handleFormatForDualNdef(tag: Tag) {
        val ok = NDEFHelper.formatPiccForDualNdef(tag, debug = true)
        runOnUiThread {
            if (ok) {
                statusText.text = "Card formatted & NDEF initialised"
                Toast.makeText(this, "PICC formatted for Dual NDEF", Toast.LENGTH_SHORT).show()
            } else {
                statusText.text = "Format for Dual NDEF failed (see logcat)"
                Toast.makeText(this, "Format Dual NDEF failed", Toast.LENGTH_LONG).show()
            }
            pendingAction = PendingAction.NONE
        }
    }


    private fun handleWriteDualNdef(tag: Tag) {
        val helper = NDEFHelper.connect(tag, debug = true)
        if (helper == null) {
            runOnUiThread {
                statusText.text = "Dual write: IsoDep / DESFire connect failed"
                Toast.makeText(this, "DESFire connection failed", Toast.LENGTH_SHORT).show()
                pendingAction = PendingAction.NONE
            }
            return
        }

        try {
            val isPoc = (getSplitMode() == SPLIT_MODE_POC)

            // --- RO (Type-4 NDEF) ---
            val roMime: String
            val npsBytes: ByteArray

            if (isPoc) {
                val roText = textHistoric.text?.toString().orEmpty()
                    .ifBlank { """{"type":"historic","msg":"NPS default"}""" }

                roMime = "application/x.nps.v1-0"
                npsBytes = roText.toByteArray(Charsets.UTF_8)

                // Keep vars consistent (plaintext)
                roBytes = npsBytes
                roGzipBytes = null
                roIsGzip = false
                roIsPlaintext = true
                roPlainText = roText
            } else {
                roMime = MIME_NPS_GZ
                npsBytes = ensureGzipBytesForWrite(
                    preferredGzip = roGzipBytes,
                    editText = textHistoric,
                    fallbackJson = """{"type":"historic","msg":"NPS default"}"""
                )

                roBytes = npsBytes
                roGzipBytes = npsBytes
                roIsGzip = true
                roIsPlaintext = false
                roPlainText = null
            }

            // --- RW (DESFire extra) — always gzip-binary ---
            val rwMime = MIME_EXT_GZ
            val extraBytes = ensureGzipBytesForWrite(
                preferredGzip = rwGzipBytes,
                editText = textRw,
                fallbackJson = """{"type":"rw","msg":"Default RW extra data"}"""
            )

            // Keep RW vars consistent (gzip)
            rwBytes = extraBytes
            rwGzipBytes = extraBytes
            rwIsGzip = true

            // If RO part doesn't fit current 000001/E104 capacity, reformat PICC for Dual
            val roFits = helper.canWriteType4NdefRo(roMime, npsBytes)
            if (!roFits) {
                val requiredCapacity = helper.requiredType4Capacity(roMime, npsBytes)
                val newCapacity = helper.chooseNdefCapacity(requiredCapacity)

                helper.close() // must close before reformat (new IsoDep session)

                val formatted = NDEFHelper.formatPiccForDualNdef(
                    tag = tag,
                    debug = true,
                    seedMimeType = "application/x.nps.v1-0",
                    seedPayload = """{"type":"seed","msg":"Dual reformat"}""".toByteArray(),
                    ndefCapacityBytes = newCapacity
                )

                if (!formatted) {
                    runOnUiThread {
                        statusText.text = "Dual write FAILED: could not reformat card for larger RO NDEF"
                        pendingAction = PendingAction.NONE
                    }
                    return
                }

                // reconnect after format
                val helper2 = NDEFHelper.connect(tag, debug = true)
                if (helper2 == null) {
                    runOnUiThread {
                        statusText.text = "Dual write FAILED: reconnect after reformat failed"
                        pendingAction = PendingAction.NONE
                    }
                    return
                }

                try {
                    val ok = helper2.writeDualSectionNdef(
                        roMimeType = roMime,
                        roPayload  = npsBytes,
                        rwMimeType = rwMime,
                        rwPayload  = extraBytes
                    )

                    runOnUiThread {
                        statusText.text = if (ok) {
                            "Dual write OK (auto-resized RO NDEF)"
                        } else {
                            "Dual write FAILED"
                        }
                        refreshTextViewsFromBytes()
                        updateTabSizes()
                        pendingAction = PendingAction.NONE
                    }
                } finally {
                    helper2.close()
                }
                return
            }

            // Normal path (fits)
            val ok = helper.writeDualSectionNdef(
                roMimeType = roMime,
                roPayload  = npsBytes,
                rwMimeType = rwMime,
                rwPayload  = extraBytes
            )

            runOnUiThread {
                statusText.text = if (ok) {
                    "Dual write OK: Type-4 NDEF (RO) + DESFire extra (RW)"
                } else {
                    "Dual write FAILED"
                }
                refreshTextViewsFromBytes()
                updateTabSizes()
                pendingAction = PendingAction.NONE
            }

        } catch (e: Exception) {
            e.printStackTrace()
            runOnUiThread {
                statusText.text = "Error during Dual write: ${e.message}"
                pendingAction = PendingAction.NONE
            }
        } finally {
            // note: may already be closed earlier in the resize path; safe anyway
            try { helper.close() } catch (_: Exception) {}
        }
    }





    private fun handleFormat(helper: DesfireHelper) {
        val ok = helper.formatPicc()

        runOnUiThread {
            statusText.text = if (ok) {
                "Card formatted: all DESFire apps & files removed"
            } else {
                "Format failed – see log"
            }
            pendingAction = PendingAction.NONE
        }
    }



    private fun handleWrite(helper: DesfireHelper) {

        val isPoc = (getSplitMode() == SPLIT_MODE_POC)

        // --- RO / historic ---
        val historicBytes: ByteArray =
            if (isPoc) {
                val roText = textHistoric.text?.toString().orEmpty()
                    .ifBlank { dummyHistoricPayload.toString(Charsets.UTF_8) }

                // POC rule: part 1 is plaintext
                roBytes = roText.toByteArray(Charsets.UTF_8)
                roGzipBytes = null
                roIsGzip = false
                roIsPlaintext = true
                roPlainText = roText

                roBytes
            } else {
                // Unified rule: part 1 is gzip-binary
                val gz = ensureGzipBytesForWrite(
                    preferredGzip = roGzipBytes,
                    editText = textHistoric,
                    fallbackJson = dummyHistoricPayload.toString(Charsets.UTF_8)
                )

                roBytes = gz
                roGzipBytes = gz
                roIsGzip = true
                roIsPlaintext = false
                roPlainText = null

                gz
            }

        // --- RW (always gzip-binary) ---
        val rwBytesOut = ensureGzipBytesForWrite(
            preferredGzip = rwGzipBytes,
            editText = textRw,
            fallbackJson = dummyRwPayload.toString(Charsets.UTF_8)
        )

        rwBytes = rwBytesOut
        rwGzipBytes = rwBytesOut
        rwIsGzip = true

        val ok = helper.writeTestPayload(historic = historicBytes, rw = rwBytesOut)

        val versionSummary = helper.getVersionSummary() ?: "Version: (error or not supported)"
        val uid = helper.getUidHex() ?: "UID: (unavailable)"

        runOnUiThread {
            statusText.text = if (ok) {
                "WRITE to card OK\n$versionSummary\nUID: $uid"
            } else {
                "WRITE to card FAILED\n$versionSummary\nUID: $uid"
            }
            refreshTextViewsFromBytes()
            updateTabSizes()
            pendingAction = PendingAction.NONE
        }
    }






    private fun handleRead(helper: DesfireHelper) {
        val payload = helper.readTestPayload()

        val versionSummary = helper.getVersionSummary() ?: "Version: (error or not supported)"
        val uid = helper.getUidHex() ?: "UID: (unavailable)"

        runOnUiThread {
            if (payload == null) {
                statusText.text = "READ from card FAILED\n$versionSummary\nUID: $uid"
            } else {
                roBytes = payload.historic
                rwBytes = payload.rw

                roGzipBytes = roBytes
                rwGzipBytes = rwBytes

                refreshTextViewsFromBytes()
                statusText.text = "READ from card OK\n$versionSummary\nUID: $uid"
            }

            updateTabSizes()
            pendingAction = PendingAction.NONE
        }
    }

}
