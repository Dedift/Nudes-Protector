package mm.nudesprotector.domain.dto.request

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern

data class MfaVerifyRequest(
    @field:NotBlank
    @field:Pattern(regexp = "\\d{6}")
    val code: String?,
)
