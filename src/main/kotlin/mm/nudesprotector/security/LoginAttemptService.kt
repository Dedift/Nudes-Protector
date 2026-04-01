package mm.nudesprotector.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service
import java.time.Duration

@Service
class LoginAttemptService(
    private val redisTemplate: StringRedisTemplate,
    @Value($$"${app.security.login.max-failed-attempts:5}")
    private val maxFailedAttempts: Long,
    @Value($$"${app.security.login.lock-duration:PT15M}")
    private val lockDuration: Duration,
) {
    fun registerFailure(email: String): LoginFailureOutcome {
        val normalizedEmail = normalizeEmail(email)
        val attemptsKey = attemptsKey(normalizedEmail)
        val lockKey = lockKey(normalizedEmail)
        val attempts = redisTemplate.opsForValue().increment(attemptsKey) ?: 0L

        redisTemplate.expire(attemptsKey, lockDuration)
        return if (attempts >= maxFailedAttempts) {
            redisTemplate.opsForValue().set(lockKey, "1", lockDuration)
            redisTemplate.delete(attemptsKey)
            LoginFailureOutcome(locked = true)
        } else {
            LoginFailureOutcome(locked = false)
        }
    }

    fun resetFailures(email: String) {
        val normalizedEmail = normalizeEmail(email)
        redisTemplate.delete(listOf(attemptsKey(normalizedEmail), lockKey(normalizedEmail)))
    }

    fun isLocked(email: String): Boolean =
        redisTemplate.hasKey(lockKey(normalizeEmail(email))) == true

    private fun attemptsKey(email: String): String = "auth:failed:$email"

    private fun lockKey(email: String): String = "auth:locked:$email"

    private fun normalizeEmail(email: String): String = email.trim().lowercase()
}

data class LoginFailureOutcome(
    val locked: Boolean,
)
