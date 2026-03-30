package mm.nudesprotector.repository

import mm.nudesprotector.domain.EmailVerificationCode
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import reactor.core.publisher.Mono
import java.util.UUID

interface EmailVerificationCodeRepository : ReactiveCrudRepository<EmailVerificationCode, UUID> {
    fun findByUserIdAndCode(userId: UUID, code: String): Mono<EmailVerificationCode>
    fun deleteByUserId(userId: UUID): Mono<Void>
}
