package mm.nudesprotector.service

import mm.nudesprotector.domain.EmailVerificationCode
import mm.nudesprotector.domain.User
import mm.nudesprotector.domain.dto.request.CreateUserRequest
import mm.nudesprotector.domain.dto.request.LoginUserRequest
import mm.nudesprotector.domain.dto.request.VerifyEmailRequest
import mm.nudesprotector.domain.dto.response.CreateUserResponse
import mm.nudesprotector.domain.dto.response.LoginUserResponse
import mm.nudesprotector.domain.dto.response.VerifyEmailResponse
import mm.nudesprotector.repository.EmailVerificationCodeRepository
import mm.nudesprotector.repository.UserRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.time.Duration
import java.time.Instant
import kotlin.random.Random

@Service
class Service(
    private val userRepository: UserRepository,
    private val emailVerificationCodeRepository: EmailVerificationCodeRepository,
    private val emailVerificationMailService: EmailVerificationMailService,
    private val passwordEncoder: PasswordEncoder,
    @Value($$"${app.mail.verification.ttl}")
    private val verificationCodeTtl: Duration,
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
                                .flatMap { savedUser ->
                                    val userId = checkNotNull(savedUser.id)
                                    val verificationCode = generateVerificationCode()

                                    emailVerificationCodeRepository.deleteByUserId(userId)
                                        .then(
                                            emailVerificationCodeRepository.save(
                                                EmailVerificationCode(
                                                    userId = userId,
                                                    code = verificationCode,
                                                    expiresAt = Instant.now().plus(verificationCodeTtl),
                                                ),
                                            ),
                                        )
                                        .then(emailVerificationMailService.sendVerificationCode(savedUser.email, verificationCode))
                                        .thenReturn(savedUser)
                                }
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

    fun verifyEmail(request: VerifyEmailRequest): Mono<VerifyEmailResponse> {
        val email = requireNotNull(request.email).trim().lowercase()
        val code = requireNotNull(request.code).trim()

        return userRepository.findByEmailIgnoreCase(email)
            .switchIfEmpty(Mono.error(IllegalArgumentException("User with email '$email' was not found")))
            .flatMap { user ->
                if (user.emailVerified) {
                    Mono.just(
                        VerifyEmailResponse(
                            verified = true,
                            message = "Email is already verified",
                        ),
                    )
                } else {
                    val userId = checkNotNull(user.id)

                    emailVerificationCodeRepository.findByUserIdAndCode(userId, code)
                        .switchIfEmpty(Mono.error(IllegalArgumentException("Invalid verification code")))
                        .flatMap { verificationCode ->
                            if (verificationCode.expiresAt.isBefore(Instant.now())) {
                                emailVerificationCodeRepository.deleteByUserId(userId)
                                    .then(Mono.error(IllegalArgumentException("Verification code expired")))
                            } else {
                                userRepository.save(user.copy(emailVerified = true))
                                    .then(emailVerificationCodeRepository.deleteByUserId(userId))
                                    .thenReturn(
                                        VerifyEmailResponse(
                                            verified = true,
                                            message = "Email verified successfully",
                                        ),
                                    )
                            }
                        }
                }
            }
    }

    private fun generateVerificationCode(): String = Random.nextInt(100000, 1_000_000).toString()
}
