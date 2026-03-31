package mm.nudesprotector.service

import mm.nudesprotector.domain.User
import mm.nudesprotector.domain.dto.request.CreateUserRequest
import mm.nudesprotector.domain.dto.response.CreateUserResponse
import mm.nudesprotector.mail.EmailVerificationService
import mm.nudesprotector.repository.UserRepository
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers

@Service
class UserRegistrationService(
    private val userRepository: UserRepository,
    private val emailVerificationService: EmailVerificationService,
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
            .flatMap { savedUser ->
                emailVerificationService.issueCodeForUser(savedUser)
                    .thenReturn(savedUser)
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
}
