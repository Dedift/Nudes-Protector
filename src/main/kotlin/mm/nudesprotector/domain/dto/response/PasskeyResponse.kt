package mm.nudesprotector.domain.dto.response

import java.time.Instant

data class PasskeyResponse(
    val id: String,
    val label: String?,
    val createdAt: Instant,
    val lastUsedAt: Instant,
    val transports: Set<String>,
)
