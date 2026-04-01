package mm.nudesprotector.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service
import java.security.SecureRandom
import java.time.Duration
import java.util.UUID

@Service
class MfaOtpService(
    private val redisTemplate: StringRedisTemplate,
    @Value("\${app.mfa.otp-ttl:PT5M}")
    private val otpTtl: Duration,
    @Value("\${app.mfa.max-failed-attempts:3}")
    private val maxFailedAttempts: Long,
) {
    private val secureRandom = SecureRandom()

    fun issueOtp(userId: UUID): String {
        val code = generateCode()
        redisTemplate.opsForValue().set(otpKey(userId), code, otpTtl)
        redisTemplate.delete(listOf(attemptsKey(userId)))
        return code
    }

    fun verify(userId: UUID, submittedCode: String): MfaVerificationResult {
        val storedCode = redisTemplate.opsForValue().get(otpKey(userId))
            ?: return MfaVerificationResult.EXPIRED

        return if (storedCode == submittedCode) {
            clear(userId)
            MfaVerificationResult.SUCCESS
        } else {
            registerFailedAttempt(userId)
        }
    }

    private fun registerFailedAttempt(userId: UUID): MfaVerificationResult {
        val attempts = redisTemplate.opsForValue().increment(attemptsKey(userId)) ?: 0L
        redisTemplate.expire(attemptsKey(userId), otpTtl)
        return if (attempts >= maxFailedAttempts) {
            MfaVerificationResult.REISSUE_REQUIRED
        } else {
            MfaVerificationResult.INVALID
        }
    }

    fun clear(userId: UUID) {
        redisTemplate.delete(listOf(otpKey(userId), attemptsKey(userId)))
    }

    private fun otpKey(userId: UUID): String = "mfa:otp:$userId"

    private fun attemptsKey(userId: UUID): String = "mfa:attempts:$userId"

    private fun generateCode(): String = secureRandom.nextInt(1_000_000).toString().padStart(6, '0')
}

enum class MfaVerificationResult {
    SUCCESS,
    INVALID,
    EXPIRED,
    REISSUE_REQUIRED,
}
