package mm.nudesprotector.mail

import mm.nudesprotector.domain.User
import mm.nudesprotector.domain.dto.request.VerifyEmailRequest
import mm.nudesprotector.domain.dto.response.VerifyEmailResponse
import mm.nudesprotector.repository.UserRepository
import org.springframework.stereotype.Service
import java.time.Instant

@Service
class EmailVerificationService(
    private val userRepository: UserRepository,
    private val verificationCodeService: VerificationCodeService,
    private val mailService: MailService,
) {
    fun issueCodeForUser(user: User) {
        val userId = checkNotNull(user.id)
        val code = verificationCodeService.replaceCode(userId)

        mailService.sendTextMail(
            email = user.email,
            subject = "Email verification code",
            text = "Your email verification code is: $code",
        )
    }

    fun verifyEmail(request: VerifyEmailRequest): VerifyEmailResponse {
        val email = requireNotNull(request.email).trim().lowercase()
        val code = requireNotNull(request.code).trim()
        val user = userRepository.findByEmailIgnoreCase(email)
            ?: throw IllegalArgumentException("User with email '$email' was not found")

        return if (user.emailVerified) {
            VerifyEmailResponse(
                verified = true,
                message = "Email is already verified",
            )
        } else {
            verifyCode(user, code)
        }
    }

    private fun verifyCode(user: User, code: String): VerifyEmailResponse {
        val userId = checkNotNull(user.id)
        val verificationCode = verificationCodeService.findByUserIdAndCode(userId, code)
            ?: throw IllegalArgumentException("Invalid verification code")

        if (verificationCode.expiresAt.isBefore(Instant.now())) {
            verificationCodeService.deleteByUserId(userId)
            throw IllegalArgumentException("Verification code expired")
        }

        userRepository.save(user.copy(emailVerified = true))
        verificationCodeService.deleteByUserId(userId)
        return VerifyEmailResponse(
            verified = true,
            message = "Email verified successfully",
        )
    }
}
