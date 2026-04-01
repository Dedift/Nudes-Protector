package mm.nudesprotector.mail

import mm.nudesprotector.domain.EmailVerificationCode
import mm.nudesprotector.repository.EmailVerificationCodeRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.random.Random

@Service
class VerificationCodeService(
    private val emailVerificationCodeRepository: EmailVerificationCodeRepository,
    @Value($$"${app.mail.verification.ttl:PT15M}")
    private val verificationCodeTtl: Duration,
) {
    fun replaceCode(userId: UUID): String {
        val code = generateVerificationCode()

        emailVerificationCodeRepository.deleteByUserId(userId)
        emailVerificationCodeRepository.save(
            EmailVerificationCode(
                userId = userId,
                code = code,
                expiresAt = Instant.now().plus(verificationCodeTtl),
            )
        )
        return code
    }

    fun findByUserIdAndCode(userId: UUID, code: String): EmailVerificationCode? =
        emailVerificationCodeRepository.findByUserIdAndCode(userId, code)

    fun deleteByUserId(userId: UUID) {
        emailVerificationCodeRepository.deleteByUserId(userId)
    }

    private fun generateVerificationCode(): String = Random.nextInt(100000, 1_000_000).toString()
}
