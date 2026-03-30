package mm.nudesprotector.service

import mm.nudesprotector.domain.User
import mm.nudesprotector.domain.dto.request.CreateUserRequest
import mm.nudesprotector.domain.dto.request.LoginUserRequest
import mm.nudesprotector.domain.dto.response.CreateUserResponse
import mm.nudesprotector.domain.dto.response.LoginUserResponse
import mm.nudesprotector.repository.UserRepository
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers

@Service
class Service(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
) {
    fun createUser(request: CreateUserRequest): Mono<CreateUserResponse> {
        val normalizedEmail = requireNotNull(request.email).trim().lowercase()
        val normalizedUsername = requireNotNull(request.username).trim()
        val rawPassword = requireNotNull(request.password)

        return Mono.fromCallable {
            requireNotNull(passwordEncoder.encode(rawPassword)) {
                "Password encoder returned null hash"
            }
        }
            .subscribeOn(Schedulers.boundedElastic())
            .flatMap { encodedPassword ->
                userRepository.existsByEmailIgnoreCase(normalizedEmail)
                    .flatMap { emailExists ->
                        if (emailExists) {
                            Mono.error(IllegalArgumentException("User with email '$normalizedEmail' already exists"))
                        } else {
                            userRepository.save(
                                User(
                                    username = normalizedUsername,
                                    email = normalizedEmail,
                                    passwordHash = encodedPassword,
                                ),
                            )
                        }
                    }
            }
            .map { savedUser ->
                CreateUserResponse(
                    id = checkNotNull(savedUser.id),
                    username = savedUser.username,
                    email = savedUser.email,
                    emailVerified = savedUser.emailVerified,
                    createdAt = savedUser.createdAt,
                )
            }
            .switchIfEmpty(
                Mono.error(IllegalStateException("User registration finished without a saved user")),
            )
    }

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
