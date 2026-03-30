package mm.nudesprotector.domain.dto.response

import java.util.UUID

data class LoginUserResponse(
    val id: UUID,
    val username: String,
    val email: String,
    val emailVerified: Boolean,
)
