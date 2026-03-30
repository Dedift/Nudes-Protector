package mm.nudesprotector.domain.dto.response

import java.time.Instant
import java.util.UUID

data class CreateUserResponse(
    val id: UUID,
    val username: String,
    val email: String,
    val emailVerified: Boolean,
    val createdAt: Instant,
)
