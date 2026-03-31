package mm.nudesprotector.domain.dto.request

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

data class MfaLoginRequest(
    @field:NotBlank
    @field:Email
    val email: String?,
    @field:NotBlank
    @field:Size(min = 8, max = 255)
    val password: String?,
)
