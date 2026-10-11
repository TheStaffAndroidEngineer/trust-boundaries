package staff.android.trust

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val BodyFont = FontFamily(Font(R.font.google_sans_regular), Font(R.font.google_sans_bold, FontWeight.Bold))
private val DisplayFont = FontFamily(Font(R.font.sora_bold, FontWeight.Bold))
private val Light = lightColorScheme(
    primary = Color(0xFF3156D3), onPrimary = Color.White,
    primaryContainer = Color(0xFFEBEFFE), onPrimaryContainer = Color(0xFF243F9E),
    secondary = Color(0xFF526263), onSecondary = Color.White,
    background = Color.White, onBackground = Color(0xFF192327),
    surface = Color.White, onSurface = Color(0xFF192327),
    surfaceVariant = Color(0xFFF1F4F6), onSurfaceVariant = Color(0xFF58656E),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFF7F9FA),
    surfaceContainer = Color(0xFFF3F5F7), surfaceContainerHigh = Color(0xFFF1F4F6),
    surfaceContainerHighest = Color(0xFFE8ECEF), surfaceTint = Color(0xFF3156D3),
    outline = Color(0xFF74828D), outlineVariant = Color(0xFFE4E8EB),
    error = Color(0xFFB23829), onError = Color.White,
)
private val Dark = darkColorScheme(
    primary = Color(0xFFB5C4FF), onPrimary = Color(0xFF162D77),
    primaryContainer = Color(0xFF293E7C), onPrimaryContainer = Color(0xFFDDE4FF),
    secondary = Color(0xFFB4C8C8), background = Color(0xFF12181D), onBackground = Color(0xFFEBEFF1),
    surface = Color(0xFF12181D), onSurface = Color(0xFFEBEFF1),
    surfaceVariant = Color(0xFF202A32), onSurfaceVariant = Color(0xFFB6C0C8),
    surfaceContainerLowest = Color(0xFF0D1216), surfaceContainerLow = Color(0xFF172026),
    surfaceContainer = Color(0xFF1C252D), surfaceContainerHigh = Color(0xFF202A32),
    surfaceContainerHighest = Color(0xFF29353E), surfaceTint = Color(0xFFB5C4FF),
    outline = Color(0xFF87929A), outlineVariant = Color(0xFF35424B),
)
private val CommonTypography = Typography(
    displaySmall = TextStyle(fontFamily = DisplayFont, fontWeight = FontWeight.Bold, fontSize = 32.sp, lineHeight = 39.sp, letterSpacing = (-1).sp),
    headlineLarge = TextStyle(fontFamily = DisplayFont, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 35.sp, letterSpacing = (-0.7).sp),
    headlineMedium = TextStyle(fontFamily = DisplayFont, fontWeight = FontWeight.Bold, fontSize = 24.sp, lineHeight = 31.sp, letterSpacing = (-0.6).sp),
    headlineSmall = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Bold, fontSize = 22.sp, lineHeight = 29.sp),
    titleLarge = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 27.sp),
    titleMedium = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Bold, fontSize = 16.sp, lineHeight = 23.sp),
    titleSmall = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Bold, fontSize = 14.sp, lineHeight = 21.sp),
    bodyLarge = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Normal, fontSize = 16.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Normal, fontSize = 14.sp, lineHeight = 21.sp),
    bodySmall = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 18.sp),
    labelLarge = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Bold, fontSize = 14.sp, lineHeight = 20.sp),
    labelMedium = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Bold, fontSize = 12.sp, lineHeight = 18.sp),
    labelSmall = TextStyle(fontFamily = BodyFont, fontWeight = FontWeight.Normal, fontSize = 11.sp, lineHeight = 15.sp),
)

@Composable fun CommonTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (darkTheme) Dark else Light, typography = CommonTypography, content = content)
}
