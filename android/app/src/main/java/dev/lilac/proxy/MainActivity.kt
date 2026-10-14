package dev.lilac.proxy

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.snackbar.Snackbar
import dev.lilac.proxy.databinding.ActivityMainBinding
import dev.lilac.proxy.databinding.ItemDcBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var settings: Settings
    private val dcInputs = LinkedHashMap<Int, ItemDcBinding>()

    private val askNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* статус виден и без него */ }

    private val refresh = { render() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        settings = Settings(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            askNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        fillFields()
        buildDcRows()
        wireControls()

        ProxyState.subscribe(refresh)
        ProxyState.log.subscribe { lines ->
            runOnUiThread {
                binding.logsText.text = if (lines.isEmpty()) getString(R.string.logs_empty) else lines.joinToString("\n")
            }
        }
        render()
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    override fun onPause() {
        super.onPause()
        saveFields()
    }

    private fun fillFields() {
        binding.secretInput.setText(settings.secretHex)
        binding.portInput.setText(settings.port.toString())
        binding.switchWs.isChecked = settings.preferWs
        binding.switchTcp.isChecked = settings.tcpFallback
    }

    private fun wireControls() {
        binding.btnToggle.setOnClickListener {
            if (ProxyState.running) {
                ProxyService.stop(this)
            } else if (saveFields()) {
                ProxyService.start(this)
            }
        }
        binding.btnSecretNew.setOnClickListener {
            settings.secretHex = ProxyConfig.randomSecretHex()
            binding.secretInput.setText(settings.secretHex)
            restartIfNeeded()
        }
        binding.btnCopyLink.setOnClickListener { copyLink() }
        binding.btnOpenTelegram.setOnClickListener { openInTelegram() }
        binding.btnLogsClear.setOnClickListener { ProxyState.log.clear() }

        binding.switchWs.setOnCheckedChangeListener { _, checked ->
            settings.preferWs = checked
            restartIfNeeded()
        }
        binding.switchTcp.setOnCheckedChangeListener { _, checked ->
            settings.tcpFallback = checked
            restartIfNeeded()
        }
        binding.secretInput.onTextChanged { settings.secretHex = it.lowercase() }
        binding.portInput.onTextChanged { text ->
            text.toIntOrNull()?.takeIf { port -> port in 1024..65535 }?.let { port -> settings.port = port }
        }
        binding.portInput.setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) {
                saveFields()
                restartIfNeeded()
                true
            } else {
                false
            }
        }
    }

    private fun buildDcRows() {
        val overrides = settings.dcOverrides
        Targets.DC_DEFAULT_IPS.keys.sorted().forEach { dc ->
            val row = ItemDcBinding.inflate(layoutInflater, binding.dcContainer, false)
            row.dcTitle.text = Targets.DC_TITLES[dc] ?: "DC$dc"
            row.dcDefault.text = buildString {
                append("fallback: ").append(Targets.DC_DEFAULT_IPS[dc])
                Targets.wsDomains(dc, isMedia = false).firstOrNull()?.let { append("   ·   ws: ").append(it) }
            }
            row.dcCustom.setText(overrides[dc].orEmpty())
            row.dcCustom.onTextChanged { text ->
                val current = settings.dcOverrides.toMutableMap()
                if (text.isBlank()) current.remove(dc) else current[dc] = text.trim()
                settings.dcOverrides = current
            }
            dcInputs[dc] = row
            binding.dcContainer.addView(row.root)
        }
    }

    /** true — значения корректны и сохранены. */
    private fun saveFields(): Boolean {
        val secret = binding.secretInput.text?.toString()?.trim().orEmpty()
        val parsed = runCatching { Obfs2.parseSecret(secret) }.isSuccess
        binding.secretInput.error = if (parsed) null else getString(R.string.secret_invalid)
        if (!parsed) return false

        val port = binding.portInput.text?.toString()?.toIntOrNull()
        if (port == null || port !in 1024..65535) {
            binding.portInput.error = "1024–65535"
            return false
        }
        settings.port = port
        return true
    }

    private fun restartIfNeeded() {
        if (ProxyState.running) {
            ProxyService.stop(this)
            ProxyService.start(this)
        }
    }

    private fun currentLink(): String = Targets.telegramLink(
        host = "127.0.0.1",
        port = settings.port,
        secretHex = settings.secretHex,
    )

    private fun copyLink() {
        val manager = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        manager.setPrimaryClip(ClipData.newPlainText("lilac", currentLink()))
        Toast.makeText(this, R.string.copy_link, Toast.LENGTH_SHORT).show()
    }

    private fun openInTelegram() {
        if (!saveFields()) return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(currentLink())))
        } catch (error: ActivityNotFoundException) {
            Snackbar.make(binding.root, R.string.telegram_missing, Snackbar.LENGTH_LONG).show()
        }
    }

    private fun render() {
        val running = ProxyState.running
        binding.btnToggle.setText(if (running) R.string.stop else R.string.start)
        binding.statusPill.text = if (running) {
            getString(R.string.status_running, ProxyState.port)
        } else {
            getString(R.string.status_idle)
        }
        binding.statusPill.setBackgroundResource(if (running) R.drawable.bg_pill_active else R.drawable.bg_pill)
        binding.statusPill.setTextColor(
            ContextCompat.getColor(this, if (running) R.color.accent else R.color.text_muted)
        )

        val stats = ProxyState.stats
        binding.statTotal.text = stats.connectionsTotal.get().toString()
        binding.statActive.text = stats.connectionsActive.get().toString()
        binding.statWs.text = stats.connectionsWs.get().toString()
        binding.statTcp.text = stats.connectionsTcp.get().toString()
        binding.statBad.text = stats.connectionsBad.get().toString()
        binding.statUp.text = humanBytes(stats.bytesUp.get())
        binding.statDown.text = humanBytes(stats.bytesDown.get())

        val error = stats.lastError
        binding.lastError.visibility = if (error == null || running) View.GONE else View.VISIBLE
        binding.lastError.text = error.orEmpty()
    }

    private fun watcher(onChanged: (String) -> Unit): TextWatcher = object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
        override fun afterTextChanged(s: Editable?) = afterTextChangedValue(s, onChanged)
    }

    private fun afterTextChangedValue(s: Editable?, onChanged: (String) -> Unit) {
        onChanged(s?.toString().orEmpty())
    }

    private fun android.widget.EditText.onTextChanged(handler: (String) -> Unit) {
        addTextChangedListener(watcher(handler))
    }
}
