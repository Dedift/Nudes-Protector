package mm.nudesprotector.service

import mm.nudesprotector.domain.dto.request.LoginUserRequest
import mm.nudesprotector.domain.dto.response.LoginUserResponse
import mm.nudesprotector.repository.UserRepository
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers

@Service
class UserLoginService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
) {
    fun loginUser(request: LoginUserRequest): Mono<LoginUserResponse> {
        val email = requireNotNull(request.email).trim().lowercase()
        val rawPassword = requireNotNull(request.password)

        return userRepository.findByEmailIgnoreCase(email)
            .switchIfEmpty(Mono.error(IllegalArgumentException("Invalid email or password")))
            .flatMap { user ->
                Mono.fromCallable { passwordEncoder.matches(rawPassword, user.passwordHash) }
                    .subscribeOn(Schedulers.boundedElastic())
                    .flatMap { passwordMatches ->
                        if (passwordMatches) {
                            Mono.just(
                                LoginUserResponse(
                                    id = checkNotNull(user.id),
                                    username = user.username,
                                    email = user.email,
                                    emailVerified = user.emailVerified,
                                ),
                            )
                        } else {
                            Mono.error(IllegalArgumentException("Invalid email or password"))
                        }
                    }
            }
    }
}
