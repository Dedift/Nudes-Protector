package mm.nudesprotector.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.stereotype.Service
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.security.SecureRandom
import java.time.Duration
import java.util.UUID

@Service
class MfaOtpService(
    private val redisTemplate: ReactiveStringRedisTemplate,
    @Value("\${app.mfa.otp-ttl:PT5M}")
    private val otpTtl: Duration,
    @Value("\${app.mfa.max-failed-attempts:3}")
    private val maxFailedAttempts: Long,
) {
    private val secureRandom = SecureRandom()

    fun issueOtp(userId: UUID): Mono<String> {
        val code = generateCode()
        return redisTemplate.opsForValue().set(otpKey(userId), code, otpTtl)
            .then(redisTemplate.delete(Flux.just(attemptsKey(userId))).then())
            .thenReturn(code)
    }

    fun verify(userId: UUID, submittedCode: String): Mono<MfaVerificationResult> =
        redisTemplate.opsForValue().get(otpKey(userId))
            .flatMap { storedCode ->
                if (storedCode == submittedCode) {
                    clear(userId).thenReturn(MfaVerificationResult.SUCCESS)
                } else {
                    registerFailedAttempt(userId)
                }
            }
            .switchIfEmpty(Mono.just(MfaVerificationResult.EXPIRED))

    private fun registerFailedAttempt(userId: UUID): Mono<MfaVerificationResult> =
        redisTemplate.opsForValue().increment(attemptsKey(userId))
            .flatMap { attempts ->
                redisTemplate.expire(attemptsKey(userId), otpTtl)
                    .thenReturn(
                        if (attempts >= maxFailedAttempts) {
                            MfaVerificationResult.REISSUE_REQUIRED
                        } else {
                            MfaVerificationResult.INVALID
                        },
                    )
            }

    fun clear(userId: UUID): Mono<Void> =
        redisTemplate.delete(Flux.just(otpKey(userId), attemptsKey(userId))).then()

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
