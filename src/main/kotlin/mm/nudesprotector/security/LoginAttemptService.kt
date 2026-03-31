package mm.nudesprotector.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.stereotype.Service
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.Duration

@Service
class LoginAttemptService(
    private val redisTemplate: ReactiveStringRedisTemplate,
    @Value($$"${app.security.login.max-failed-attempts:5}")
    private val maxFailedAttempts: Long,
    @Value($$"${app.security.login.lock-duration:PT15M}")
    private val lockDuration: Duration,
) {
    fun registerFailure(email: String): Mono<LoginFailureOutcome> {
        val normalizedEmail = normalizeEmail(email)
        val attemptsKey = attemptsKey(normalizedEmail)
        val lockKey = lockKey(normalizedEmail)

        return redisTemplate.opsForValue().increment(attemptsKey)
            .flatMap { attempts ->
                redisTemplate.expire(attemptsKey, lockDuration)
                    .then(
                        if (attempts >= maxFailedAttempts) {
                            redisTemplate.opsForValue()
                                .set(lockKey, "1", lockDuration)
                                .then(redisTemplate.delete(attemptsKey).thenReturn(LoginFailureOutcome(locked = true)))
                        } else {
                            Mono.just(LoginFailureOutcome(locked = false))
                        },
                    )
            }
    }

    fun resetFailures(email: String): Mono<Void> {
        val normalizedEmail = normalizeEmail(email)
        return redisTemplate.delete(Flux.just(attemptsKey(normalizedEmail), lockKey(normalizedEmail))).then()
    }

    fun isLocked(email: String): Mono<Boolean> =
        redisTemplate.hasKey(lockKey(normalizeEmail(email)))
            .defaultIfEmpty(false)

    private fun attemptsKey(email: String): String = "auth:failed:$email"

    private fun lockKey(email: String): String = "auth:locked:$email"

    private fun normalizeEmail(email: String): String = email.trim().lowercase()
}

data class LoginFailureOutcome(
    val locked: Boolean,
)
