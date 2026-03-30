package mm.nudesprotector.domain.dto.request

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern

data class VerifyEmailRequest(
    @field:NotBlank
    @field:Email
    val email: String,
    @field:NotBlank
    @field:Pattern(regexp = "\\d{6}", message = "Verification code must contain 6 digits")
    val code: String,
)
