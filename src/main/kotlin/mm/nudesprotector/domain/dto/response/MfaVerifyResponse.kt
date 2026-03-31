package mm.nudesprotector.domain.dto.response

data class MfaVerifyResponse(
    val authenticated: Boolean,
    val message: String,
)
