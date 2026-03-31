package mm.nudesprotector.mail

import mm.nudesprotector.domain.User
import mm.nudesprotector.domain.dto.request.VerifyEmailRequest
import mm.nudesprotector.domain.dto.response.VerifyEmailResponse
import mm.nudesprotector.repository.UserRepository
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.time.Instant

@Service
class EmailVerificationService(
    private val userRepository: UserRepository,
    private val verificationCodeService: VerificationCodeService,
    private val mailService: MailService,
) {
    fun issueCodeForUser(user: User): Mono<Void> {
        val userId = checkNotNull(user.id)

        return verificationCodeService.replaceCode(userId)
            .flatMap { code ->
                mailService.sendTextMail(
                    email = user.email,
                    subject = "Email verification code",
                    text = "Your email verification code is: $code",
                )
            }
    }

    fun verifyEmail(request: VerifyEmailRequest): Mono<VerifyEmailResponse> {
        val email = requireNotNull(request.email).trim().lowercase()
        val code = requireNotNull(request.code).trim()

        return userRepository.findByEmailIgnoreCase(email)
            .switchIfEmpty(Mono.error(IllegalArgumentException("User with email '$email' was not found")))
            .flatMap { user ->
                if (user.emailVerified) {
                    Mono.just(
                        VerifyEmailResponse(
                            verified = true,
                            message = "Email is already verified",
                        ),
                    )
                } else {
                    verifyCode(user, code)
                }
            }
    }

    private fun verifyCode(user: User, code: String): Mono<VerifyEmailResponse> {
        val userId = checkNotNull(user.id)

        return verificationCodeService.findByUserIdAndCode(userId, code)
            .switchIfEmpty(Mono.error(IllegalArgumentException("Invalid verification code")))
            .flatMap { verificationCode ->
                if (verificationCode.expiresAt.isBefore(Instant.now())) {
                    verificationCodeService.deleteByUserId(userId)
                        .then(Mono.error(IllegalArgumentException("Verification code expired")))
                } else {
                    userRepository.save(user.copy(emailVerified = true))
                        .then(verificationCodeService.deleteByUserId(userId))
                        .thenReturn(
                            VerifyEmailResponse(
                                verified = true,
                                message = "Email verified successfully",
                            ),
                        )
                }
            }
    }
}
