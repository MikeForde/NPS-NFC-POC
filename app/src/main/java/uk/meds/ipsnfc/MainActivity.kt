package uk.meds.ipsnfc

import android.content.Context
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var acr122uController: Acr122uUsbController? = null
    private var acr122uReader: Acr122uReader? = null

    // Authority data (Bytes)
    private var roBytes: ByteArray = ByteArray(0)
    private var rwBytes: ByteArray = ByteArray(0)
    
    // UI Display Tracking
    private var roIsPlaintext: Boolean = true
    private var roPlainText: String? = null
    private var roGzipBytes: ByteArray? = null
    private var rwGzipBytes: ByteArray? = null

    private val MIME_NPS_GZ = "application/x.nps.gzip.v1-0"
    private val MIME_EXT_GZ = "application/x.ext.gzip.v1-0"

    private enum class PendingAction {
        NONE, WRITE, READ, FORMAT,
        WRITE_DUAL_NDEF, FORMAT_FOR_NDEF, READ_DUAL_NDEF,
        WRITE_NATO, READ_NATO, FORMAT_NATO, CARD_INFO
    }

    private var nfcAdapter: NfcAdapter? = null
    private var pendingAction: PendingAction = PendingAction.NONE

    private val httpClient = OkHttpClient()
    private val gson = com.google.gson.GsonBuilder().setPrettyPrinting().create()
    private val nfcExec = Executors.newSingleThreadExecutor()

    private lateinit var statusText: TextView
    private lateinit var textHistoric: EditText
    private lateinit var textRw: EditText
    private lateinit var tabRoLabel: TextView
    private lateinit var tabRoSize: TextView
    private lateinit var tabRwLabel: TextView
    private lateinit var tabRwSize: TextView
    private lateinit var tabHost: TabHost

    private var ipsList: List<IpsListItem> = emptyList()
    private var selectedPackageUuid: String? = null

    private data class IpsListItem(val packageUUID: String, val given: String, val name: String) {
        fun label(): String = "$name, $given (${packageUUID.take(8)})"
    }

    private val PREFS = "ips_prefs"
    private val KEY_BASE_URL = "ips_base_url"
    private val BASE_LOCAL = "http://localhost:5049"
    private val BASE_AZURE = "https://ipsmern-dep.azurewebsites.net"
    private val KEY_POC_AUTO_DECOMPRESS = "poc_auto_decompress_rw"
    private val KEY_SPLIT_MODE = "ips_split_mode"
    private val SPLIT_MODE_UNIFIED = 0
    private val SPLIT_MODE_POC = 1
    private val KEY_PROTECT_LEVEL = "ips_protect_level"

    private fun getPocAutoDecompress(): Boolean = getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean(KEY_POC_AUTO_DECOMPRESS, true)
    private fun setPocAutoDecompress(enabled: Boolean) = getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_POC_AUTO_DECOMPRESS, enabled).apply()
    private fun getSplitMode(): Int = getSharedPreferences(PREFS, MODE_PRIVATE).getInt(KEY_SPLIT_MODE, SPLIT_MODE_UNIFIED)
    private fun setSplitMode(mode: Int) = getSharedPreferences(PREFS, MODE_PRIVATE).edit().putInt(KEY_SPLIT_MODE, mode).apply()
    private fun getIpsBase(): String = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_BASE_URL, BASE_AZURE) ?: BASE_AZURE
    private fun setIpsBase(base: String) = getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(KEY_BASE_URL, base).apply()
    private fun getProtectLevel(): Int = getSharedPreferences(PREFS, MODE_PRIVATE).getInt(KEY_PROTECT_LEVEL, 0)
    private fun setProtectLevel(level: Int) = getSharedPreferences(PREFS, MODE_PRIVATE).edit().putInt(KEY_PROTECT_LEVEL, level).apply()

    private fun ipsListUrl(): String = "${getIpsBase()}/ips/list"
    private fun ipsSplitUrl(packageUuid: String): String {
        val protect = getProtectLevel()
        val base = getIpsBase()
        return if (getSplitMode() == SPLIT_MODE_POC) "$base/ipsdatasplitpoc/$packageUuid?protect=$protect"
        else "$base/ipsunifiedsplit/$packageUuid?protect=$protect"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        textHistoric = findViewById(R.id.textHistoric)
        textRw = findViewById(R.id.textRw)

        setupTabs()
        setupButtons()
        setupSpinners()
        setupExternalReader()

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            statusText.text = "NFC not available on this device"
        }

        enableInnerScrolling(textHistoric)
        enableInnerScrolling(textRw)
        refreshIpsList()
    }

    private fun setupTabs() {
        tabHost = findViewById(android.R.id.tabhost)
        tabHost.setup()
        val (roInd, roRefs) = makeTabIndicator("DATA 1 (RO)")
        tabRoLabel = roRefs.first
        tabRoSize = roRefs.second
        val (rwInd, rwRefs) = makeTabIndicator("DATA 2 (RW)")
        tabRwLabel = rwRefs.first
        tabRwSize = rwRefs.second

        tabHost.addTab(tabHost.newTabSpec("ro").setIndicator(roInd).setContent(R.id.tab_ro))
        tabHost.addTab(tabHost.newTabSpec("rw").setIndicator(rwInd).setContent(R.id.tab_rw))
        tabHost.currentTab = 0
    }

    private fun setupButtons() {
        findViewById<ImageButton>(R.id.buttonSettings).setOnClickListener { showSettingsDialog() }
        findViewById<Button>(R.id.buttonRefreshIps).setOnClickListener { refreshIpsList() }

        findViewById<Button>(R.id.buttonWrite).setOnClickListener { setAction(PendingAction.WRITE, "WRITE mode: Tap card") }
        findViewById<Button>(R.id.buttonRead).setOnClickListener { setAction(PendingAction.READ, "READ mode: Tap card") }
        findViewById<Button>(R.id.buttonFormatApp).setOnClickListener { setAction(PendingAction.FORMAT, "FORMAT mode: Tap card") }
        findViewById<Button>(R.id.buttonWriteDualNdef).setOnClickListener { setAction(PendingAction.WRITE_DUAL_NDEF, "WRITE Dual mode: Tap card") }
        findViewById<Button>(R.id.buttonReadDual).setOnClickListener { setAction(PendingAction.READ_DUAL_NDEF, "READ Dual mode: Tap card") }
        findViewById<Button>(R.id.buttonWriteNato).setOnClickListener { setAction(PendingAction.WRITE_NATO, "WRITE NATO mode: Tap card") }
        findViewById<Button>(R.id.buttonReadNato).setOnClickListener { setAction(PendingAction.READ_NATO, "READ NATO mode: Tap card") }
        findViewById<Button>(R.id.buttonCardInfo).setOnClickListener { setAction(PendingAction.CARD_INFO, "Card Info mode: Tap card") }

        findViewById<Button>(R.id.buttonFormatForNDEF)?.setOnClickListener { setAction(PendingAction.FORMAT_FOR_NDEF, "FORMAT Dual mode: Tap card") }
        findViewById<Button>(R.id.buttonFormatForNATO)?.setOnClickListener { setAction(PendingAction.FORMAT_NATO, "FORMAT NATO mode: Tap card") }
    }

    private fun setAction(action: PendingAction, msg: String) {
        pendingAction = action
        statusText.text = msg
    }

    private fun setupSpinners() {
        findViewById<Spinner>(R.id.spinnerIps).onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>, v: View?, pos: Int, id: Long) {
                selectedPackageUuid = ipsList.getOrNull(pos)?.packageUUID
                selectedPackageUuid?.let { fetchAndShowSplit(it) }
            }
            override fun onNothingSelected(p: AdapterView<*>) { selectedPackageUuid = null }
        }
    }

    private fun setupExternalReader() {
        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager
        acr122uReader = Acr122uReader(
            usbManager = usbManager,
            onStatus = { msg -> runOnUiThread { Log.d("ACR122U", msg); statusText.text = msg } },
            onUid = { uid -> runOnUiThread { Log.d("ACR122U", "UID: $uid") } },
            onCardPresent = { transport, uid -> handleTransportDiscovered(transport, "USB ACR122U", uid) }
        )

        acr122uController = Acr122uUsbController(
            context = this,
            onStatus = { msg -> runOnUiThread { Log.d("ACR122U", msg) } },
            onReaderReady = { device -> runOnUiThread { acr122uReader?.open(device) } }
        )
        acr122uController?.start()
    }

    private fun handleTransportDiscovered(transport: ApduTransport, source: String, uid: String?) {
        val currentAction = pendingAction
        if (currentAction == PendingAction.NONE) {
            runOnUiThread { statusText.text = "$source card detected" + (if (uid != null) "\nUID: $uid" else "") }
            transport.close()
            return
        }

        nfcExec.execute {
            try {
                runOnUiThread { statusText.text = "Communicating via $source..." }
                when (currentAction) {
                    PendingAction.WRITE -> handleWrite(DesfireHelper.connect(transport, true))
                    PendingAction.READ -> handleRead(DesfireHelper.connect(transport, true))
                    PendingAction.FORMAT -> handleFormat(DesfireHelper.connect(transport, true))
                    PendingAction.WRITE_DUAL_NDEF -> handleWriteDualNdef(NDEFHelper.connect(transport, true))
                    PendingAction.READ_DUAL_NDEF -> handleReadDualNdef(NDEFHelper.connect(transport, true))
                    PendingAction.WRITE_NATO -> handleWriteNato(NATOHelper.connect(transport, true))
                    PendingAction.READ_NATO -> handleReadNato(NATOHelper.connect(transport, true))
                    PendingAction.FORMAT_FOR_NDEF -> handleFormatForDualNdef(transport)
                    PendingAction.FORMAT_NATO -> handleFormatForNato(transport)
                    PendingAction.CARD_INFO -> {
                        val report = CardInfoHelper.buildReport(transport, true).text
                        runOnUiThread { showCardInfoDialog(report) }
                    }
                    else -> transport.close()
                }
            } catch (e: Exception) {
                runOnUiThread { statusText.text = "$source error: ${e.message}" }
                transport.close()
            } finally {
                pendingAction = PendingAction.NONE
            }
        }
    }

    override fun onTagDiscovered(tag: Tag?) {
        val transport = AndroidIsoDepTransport.connect(tag ?: return) ?: return
        val uid = tag.id?.joinToString(":") { "%02X".format(it.toInt() and 0xFF) }
        handleTransportDiscovered(transport, "Internal NFC", uid)
    }

    private fun handleWrite(h: DesfireHelper) {
        val isPoc = getSplitMode() == SPLIT_MODE_POC
        val hist = if (isPoc) textHistoric.text.toString().toByteArray() else ensureGzipBytesForWrite(roGzipBytes, textHistoric, "{}")
        val rw = ensureGzipBytesForWrite(rwGzipBytes, textRw, "{}")
        val ok = h.writeTestPayload(hist, rw)
        runOnUiThread { statusText.text = if (ok) "WRITE OK" else "WRITE FAILED"; updateTabSizes() }
        h.close()
    }

    private fun handleRead(h: DesfireHelper) {
        val p = h.readTestPayload()
        if (p != null) { 
            roBytes = p.historic; rwBytes = p.rw
            roGzipBytes = roBytes; rwGzipBytes = rwBytes
            roIsPlaintext = false
            refreshTextViewsFromBytes() 
        }
        runOnUiThread { statusText.text = if (p != null) "READ OK" else "READ FAILED" }
        h.close()
    }

    private fun handleFormat(h: DesfireHelper) {
        val ok = h.formatPicc()
        runOnUiThread { statusText.text = if (ok) "FORMAT OK" else "FORMAT FAILED" }
        h.close()
    }

    private fun handleWriteDualNdef(h: NDEFHelper) {
        val isPoc = getSplitMode() == SPLIT_MODE_POC
        val ro = if (isPoc) textHistoric.text.toString().toByteArray() else ensureGzipBytesForWrite(roGzipBytes, textHistoric, "{}")
        val rw = ensureGzipBytesForWrite(rwGzipBytes, textRw, "{}")
        val ok = h.writeDualSectionNdef(if (isPoc) "text/plain" else MIME_NPS_GZ, ro, MIME_EXT_GZ, rw)
        runOnUiThread { statusText.text = if (ok) "Dual Write OK" else "Dual Write FAILED"; updateTabSizes() }
        h.close()
    }

    private fun handleReadDualNdef(h: NDEFHelper) {
        val d = h.readDualSectionNdef()
        if (d != null) { 
            d.first?.let { roBytes = it }; d.second?.let { rwBytes = it }
            roGzipBytes = d.first; rwGzipBytes = d.second
            roIsPlaintext = false
            refreshTextViewsFromBytes() 
        }
        runOnUiThread { statusText.text = if (d != null) "Dual Read OK" else "Dual Read FAILED" }
        h.close()
    }

    private fun handleWriteNato(h: NATOHelper) {
        val isPoc = getSplitMode() == SPLIT_MODE_POC
        val ro = if (isPoc) textHistoric.text.toString().toByteArray() else ensureGzipBytesForWrite(roGzipBytes, textHistoric, "{}")
        val rw = ensureGzipBytesForWrite(rwGzipBytes, textRw, "{}")
        val ok = h.writeNatoPayloads(if (isPoc) "text/plain" else MIME_NPS_GZ, ro, MIME_EXT_GZ, rw)
        runOnUiThread { statusText.text = if (ok) "NATO Write OK" else "NATO Write FAILED"; updateTabSizes() }
        h.close()
    }

    private fun handleReadNato(h: NATOHelper) {
        val p = h.readNatoPayloads()
        if (p != null) { 
            roBytes = p.npsPayload; rwBytes = p.extraPayload
            roGzipBytes = roBytes; rwGzipBytes = rwBytes
            roIsPlaintext = false
            refreshTextViewsFromBytes() 
        }
        runOnUiThread { statusText.text = if (p != null) "NATO Read OK" else "NATO Read FAILED" }
        h.close()
    }

    private fun handleFormatForDualNdef(transport: ApduTransport) {
        val ok = NDEFHelper.formatPiccForDualNdef(transport, true)
        runOnUiThread { statusText.text = if (ok) "Format Dual OK" else "Format Dual FAILED" }
    }

    private fun handleFormatForNato(transport: ApduTransport) {
        val ok = NATOHelper.formatPiccForNatoNdef(transport, true)
        runOnUiThread { statusText.text = if (ok) "Format NATO OK" else "Format NATO FAILED" }
    }

    private fun showCardInfoDialog(report: String) {
        runOnUiThread {
            val tv = TextView(this).apply { text = report; setPadding(32, 24, 32, 24); setTextIsSelectable(true); typeface = android.graphics.Typeface.MONOSPACE }
            val scroll = ScrollView(this).apply { addView(tv) }
            AlertDialog.Builder(this).setTitle("Card Info").setView(scroll).setPositiveButton("Close", null).show()
        }
    }

    private fun showSettingsDialog() {
        val baseOptions = arrayOf("Local (http://localhost:5049)", "Azure (https://ipsmern-dep.azurewebsites.net)")
        val protectOptions = arrayOf("0 — No protection", "1 — Encrypt identifiers (JWE)", "2 — Omit identifiers")
        val splitOptions = arrayOf("Unified split (RO/RW JSON)", "POC split (RO plain + RW gzipped)")

        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 24, 48, 0) }
        val baseGroup = RadioGroup(this).apply { baseOptions.forEachIndexed { i, l -> addView(RadioButton(this@MainActivity).apply { text = l; id = 1000 + i; isChecked = (i == (if (getIpsBase() == BASE_AZURE) 1 else 0)) }) } }
        val protectGroup = RadioGroup(this).apply { protectOptions.forEachIndexed { i, l -> addView(RadioButton(this@MainActivity).apply { text = l; id = 2000 + i; isChecked = (i == getProtectLevel()) }) } }
        val splitGroup = RadioGroup(this).apply { splitOptions.forEachIndexed { i, l -> addView(RadioButton(this@MainActivity).apply { text = l; id = 3000 + i; isChecked = (i == getSplitMode()) }) } }
        val autoDecompressCb = CheckBox(this).apply { text = "Auto Decompress"; isChecked = getPocAutoDecompress() }

        content.addView(TextView(this).apply { text = "API Base URL" }); content.addView(baseGroup)
        content.addView(TextView(this).apply { text = "Protect Level" }); content.addView(protectGroup)
        content.addView(TextView(this).apply { text = "Split Mode" }); content.addView(splitGroup)
        content.addView(autoDecompressCb)

        AlertDialog.Builder(this).setTitle("Settings").setView(content).setPositiveButton("Save") { _, _ ->
            setIpsBase(if (baseGroup.checkedRadioButtonId == 1001) BASE_AZURE else BASE_LOCAL)
            setProtectLevel(protectGroup.checkedRadioButtonId - 2000)
            setSplitMode(splitGroup.checkedRadioButtonId - 3000)
            setPocAutoDecompress(autoDecompressCb.isChecked)
            refreshIpsList()
        }.setNegativeButton("Cancel", null).show()
    }

    private fun refreshIpsList() {
        statusText.text = "Refreshing IPS list..."
        lifecycleScope.launch {
            try {
                val items = withContext(Dispatchers.IO) {
                    val resp = httpClient.newCall(Request.Builder().url(ipsListUrl()).build()).execute()
                    val arr = JSONArray(resp.body?.string() ?: "[]")
                    List(arr.length()) { i -> val o = arr.getJSONObject(i); IpsListItem(o.getString("packageUUID"), o.getString("given"), o.getString("name")) }
                }
                ipsList = items
                val labels = items.map { it.label() }.ifEmpty { listOf("(no records)") }
                findViewById<Spinner>(R.id.spinnerIps).adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, labels)
                statusText.text = "IPS list loaded"
            } catch (e: Exception) { statusText.text = "Load failed: ${e.message}" }
        }
    }

    private fun fetchAndShowSplit(uuid: String) {
        statusText.text = "Fetching split for $uuid..."
        lifecycleScope.launch {
            try {
                val body = withContext(Dispatchers.IO) { httpClient.newCall(Request.Builder().url(ipsSplitUrl(uuid)).build()).execute().body?.string() ?: "{}" }
                val root = JSONObject(body)
                val mode = getSplitMode()
                roIsPlaintext = false; roGzipBytes = null; rwGzipBytes = null; roPlainText = null
                if (mode == SPLIT_MODE_POC) {
                    roPlainText = root.optJSONObject("ro")?.optString("text", ""); roIsPlaintext = true
                    root.optJSONObject("rw")?.optString("bytesBase64")?.let { rwGzipBytes = android.util.Base64.decode(it, 0) }
                } else {
                    if (root.optString("encoding") == "gzip+base64") {
                        root.optString("roGzB64")?.let { if (it.isNotBlank()) roGzipBytes = android.util.Base64.decode(it, 0) }
                        root.optString("rwGzB64")?.let { if (it.isNotBlank()) rwGzipBytes = android.util.Base64.decode(it, 0) }
                    }
                }
                roBytes = roGzipBytes ?: (roPlainText ?: "").toByteArray()
                rwBytes = rwGzipBytes ?: ByteArray(0)
                refreshTextViewsFromBytes()
                statusText.text = "Split loaded"
            } catch (e: Exception) { statusText.text = "Fetch failed: ${e.message}" }
        }
    }

    private fun refreshTextViewsFromBytes() {
        val auto = getPocAutoDecompress()
        runOnUiThread {
            textHistoric.setText(bytesToUiString(roBytes, auto)); textRw.setText(bytesToUiString(rwBytes, auto))
            updateTabSizes()
        }
    }

    private fun bytesToUiString(b: ByteArray, auto: Boolean): String {
        if (b.isEmpty()) return ""
        return if (looksLikeGzip(b)) {
            if (!auto) android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP)
            else try { val s = gunzip(b).toString(Charsets.UTF_8); val p = gson.fromJson(s, Any::class.java); gson.toJson(p) } catch (_: Exception) { b.toString(Charsets.UTF_8) }
        } else {
            val s = b.toString(Charsets.UTF_8)
            runCatching { val parsed = gson.fromJson(s, Any::class.java); gson.toJson(parsed) }.getOrDefault(s)
        }
    }

    private fun ensureGzipBytesForWrite(pref: ByteArray?, et: EditText, fallback: String): ByteArray {
        if (pref != null && looksLikeGzip(pref)) return pref
        val s = et.text.toString().ifBlank { fallback }
        val out = java.io.ByteArrayOutputStream(); java.util.zip.GZIPOutputStream(out).use { it.write(s.toByteArray()) }; return out.toByteArray()
    }

    private fun gunzip(b: ByteArray): ByteArray {
        java.util.zip.GZIPInputStream(b.inputStream()).use { gis -> val out = java.io.ByteArrayOutputStream(); val buf = ByteArray(4096); while (true) { val n = gis.read(buf); if (n <= 0) break; out.write(buf, 0, n) }; return out.toByteArray() }
    }

    private fun looksLikeGzip(b: ByteArray?): Boolean = b != null && b.size >= 2 && b[0] == 0x1F.toByte() && b[1] == 0x8B.toByte()

    private fun makeTabIndicator(t: String): Pair<View, Pair<TextView, TextView>> {
        val v = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(16, 8, 16, 8); setBackgroundResource(R.drawable.tab_indicator_bg); isClickable = true }
        val t1 = TextView(this).apply { text = t; textSize = 14f }; val t2 = TextView(this).apply { text = "0 B"; textSize = 11f; alpha = 0.8f }
        v.addView(t1); v.addView(t2); return v to (t1 to t2)
    }

    private fun updateTabSizes() {
        val roSize = if (roIsPlaintext) roPlainText?.length ?: 0 else try { gunzip(roGzipBytes ?: ByteArray(0)).size } catch (_: Exception) { 0 }
        val rwSize = try { gunzip(rwGzipBytes ?: ByteArray(0)).size } catch (_: Exception) { 0 }
        tabRoSize.text = "Z: ${roGzipBytes?.size ?: 0} U: $roSize"; tabRwSize.text = "Z: ${rwGzipBytes?.size ?: 0} U: $rwSize"
    }

    private fun enableInnerScrolling(et: EditText) {
        et.setOnTouchListener { v, event -> if (v.hasFocus()) v.parent.requestDisallowInterceptTouchEvent(true); if (event.action == android.view.MotionEvent.ACTION_UP) v.parent.requestDisallowInterceptTouchEvent(false); false }
    }

    override fun onResume() { super.onResume(); enableReaderMode() }
    override fun onPause() { super.onPause(); disableReaderMode() }
    private fun enableReaderMode() { nfcAdapter?.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS, Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250) }) }
    private fun disableReaderMode() { nfcAdapter?.disableReaderMode(this) }
    override fun onDestroy() { acr122uReader?.close(); acr122uController?.stop(); super.onDestroy() }
}
