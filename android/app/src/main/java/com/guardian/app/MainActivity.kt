package com.guardian.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.guardian.app.scoring.RiskEngine
import com.guardian.app.scoring.RiskLevel
import com.guardian.app.signals.SignalCollector

/**
 * Actividad principal — Dashboard de estado Guardian.
 *
 * En el MVP se usa principalmente como pantalla de estado.
 * La evaluación real se dispara desde otras apps via Intent
 * o desde el AccessibilityService.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                GuardianDashboard()
            }
        }
    }
}

@Composable
fun GuardianDashboard() {
    val context = LocalContext.current
    var riskResult by remember {
        mutableStateOf(RiskEngine.evaluate(
            SignalCollector(context).collect("dashboard_open")
        ))
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = "Guardian",
            style = MaterialTheme.typography.headlineLarge,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Tu asistente de seguridad",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(40.dp))

        // ── Risk Card ──
        RiskCard(
            level = riskResult.level,
            score = riskResult.score,
            reasons = riskResult.reasons,
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = riskResult.recommendedAction,
            style = MaterialTheme.typography.bodyLarge,
        )

        Spacer(modifier = Modifier.height(32.dp))

        Button(onClick = {
            riskResult = RiskEngine.evaluate(
                SignalCollector(context).collect("manual_check")
            )
        }) {
            Text("Verificar ahora")
        }
    }
}

@Composable
fun RiskCard(level: RiskLevel, score: Int, reasons: List<String>) {
    val containerColor = when (level) {
        RiskLevel.LOW      -> MaterialTheme.colorScheme.secondaryContainer
        RiskLevel.MEDIUM   -> MaterialTheme.colorScheme.tertiaryContainer
        RiskLevel.HIGH     -> MaterialTheme.colorScheme.errorContainer
        RiskLevel.CRITICAL -> MaterialTheme.colorScheme.error
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(text = level.emoji, style = MaterialTheme.typography.headlineMedium)
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(text = "Riesgo ${level.label}", style = MaterialTheme.typography.titleLarge)
                    Text(text = "Score: $score / 100", style = MaterialTheme.typography.bodySmall)
                }
            }

            if (reasons.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                reasons.forEach { reason ->
                    Text(text = "• $reason", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
