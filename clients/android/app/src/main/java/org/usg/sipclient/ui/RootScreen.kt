package org.usg.sipclient.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.People
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.usg.sipclient.AppViewModel
import uniffi.client_ffi.ClassificationBanner

private enum class Tab(val label: String, val filled: ImageVector, val outlined: ImageVector) {
    DIALPAD("Dialpad", Icons.Filled.Apps, Icons.Outlined.Apps),
    CONTACTS("Contacts", Icons.Filled.People, Icons.Outlined.People),
    RECENTS("Recents", Icons.Filled.History, Icons.Outlined.History),
    SETTINGS("Settings", Icons.Filled.Settings, Icons.Outlined.Settings),
}

/**
 * Top-level layout. Ports RootView from SipClientApp.swift: a classification
 * banner strip top AND bottom (DoD convention — nothing may cover either),
 * a branding header, the tab content, the bottom nav, and the full-screen call
 * overlay + error banner sandwiched between the strips.
 */
@Composable
fun RootScreen(model: AppViewModel) {
    val banner by model.classificationBanner.collectAsState()
    val activeCall by model.activeCall.collectAsState()
    val incoming by model.incomingCall.collectAsState()
    val error by model.errorMessage.collectAsState()
    var selected by remember { mutableStateOf(Tab.DIALPAD) }
    val hasCallUi = activeCall != null || incoming != null

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing),
        ) {
            ClassificationBannerStrip(banner)
            BrandingHeader()

            Box(Modifier.weight(1f).fillMaxWidth()) {
                Column(Modifier.fillMaxSize()) {
                    Box(Modifier.weight(1f).fillMaxWidth()) {
                        when (selected) {
                            Tab.DIALPAD -> DialpadScreen(model)
                            Tab.CONTACTS -> ContactsScreen(model)
                            Tab.RECENTS -> RecentsScreen(model)
                            Tab.SETTINGS -> SettingsScreen(model)
                        }
                    }
                    NavigationBar {
                        Tab.entries.forEach { tab ->
                            val isSelected = selected == tab
                            NavigationBarItem(
                                selected = isSelected,
                                onClick = { selected = tab },
                                icon = {
                                    Icon(
                                        if (isSelected) tab.filled else tab.outlined,
                                        contentDescription = tab.label,
                                    )
                                },
                                label = { Text(tab.label) },
                            )
                        }
                    }
                }

                // The overlay covers the content area + bottom nav while a call
                // is active or ringing (CallView.swift parity). A plain
                // conditional avoids the ColumnScope/global AnimatedVisibility
                // overload ambiguity inside this Box.
                if (hasCallUi) {
                    CallOverlay(model)
                }

                ErrorBanner(error, model::dismissError, Modifier.align(Alignment.TopCenter))
            }

            ClassificationBannerStrip(banner)
        }
    }
}

/** Compact branding row: DoW seal placeholder shield plus the app title. */
@Composable
private fun BrandingHeader() {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // The Apple shell bundles a DOW-Seal.png; on Android we render a shield
        // glyph (the same fallback the Swift app uses when the asset is absent),
        // also reused as the adaptive launcher icon.
        Icon(
            Icons.Filled.Shield,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        Text(
            "  USG SIP Client",
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

/**
 * DoD-standard classification banner: a full-width strip rendering the marking
 * `LEVEL//CAVEATS//DISSEM`. Fail-safe to CUI purple until the core loads.
 */
@Composable
private fun ClassificationBannerStrip(banner: ClassificationBanner?) {
    val text = remember(banner) {
        if (banner == null) {
            "CUI"
        } else {
            buildList {
                add(banner.level)
                if (banner.caveats.isNotEmpty()) add(banner.caveats.joinToString("/"))
                if (banner.dissem.isNotEmpty()) add(banner.dissem.joinToString("/"))
            }.joinToString("//")
        }
    }
    val color = when (banner?.level) {
        "UNCLASSIFIED" -> Color(0xFF007A33)
        "CONFIDENTIAL" -> Color(0xFF0033A0)
        "SECRET" -> Color(0xFFC8102E)
        "TOP SECRET" -> Color(0xFFFF8C00)
        else -> Color(0xFF502B85) // CUI
    }
    Text(
        text = text,
        color = Color.White,
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold,
        textAlign = TextAlign.Center,
        modifier = Modifier
            .fillMaxWidth()
            .background(color)
            .padding(vertical = 3.dp),
    )
}

@Composable
private fun ErrorBanner(message: String?, onDismiss: () -> Unit, modifier: Modifier = Modifier) {
    AnimatedVisibility(
        visible = message != null,
        modifier = modifier,
        enter = slideInVertically(initialOffsetY = { -it }) + fadeIn(),
        exit = slideOutVertically(targetOffsetY = { -it }) + fadeOut(),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(12.dp)
                .background(Color(0xD9D32F2F), RoundedCornerShape(8.dp))
                .padding(10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Filled.Warning, contentDescription = null, tint = Color.White)
            Text(
                message ?: "",
                color = Color.White,
                modifier = Modifier.weight(1f),
                maxLines = 3,
            )
            IconButton(onClick = onDismiss) {
                Icon(Icons.Filled.Close, contentDescription = "Dismiss", tint = Color.White)
            }
        }
    }
}
