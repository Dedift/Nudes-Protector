package mm.nudesprotector.repository

import mm.nudesprotector.domain.User
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import reactor.core.publisher.Mono
import java.util.UUID

interface UserRepository : ReactiveCrudRepository<User, UUID> {
    fun existsByEmailIgnoreCase(email: String): Mono<Boolean>
}
