package mm.nudesprotector.service

import mm.nudesprotector.domain.User
import mm.nudesprotector.domain.dto.request.CreateUserRequest
import mm.nudesprotector.domain.dto.response.CreateUserResponse
import mm.nudesprotector.mail.EmailVerificationService
import mm.nudesprotector.repository.UserRepository
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserRegistrationService(
    private val userRepository: UserRepository,
    private val emailVerificationService: EmailVerificationService,
    private val passwordEncoder: PasswordEncoder,
) {
    fun createUser(request: CreateUserRequest): CreateUserResponse {
        val normalizedEmail = requireNotNull(request.email).trim().lowercase()
        val normalizedUsername = requireNotNull(request.username).trim()
        val rawPassword = requireNotNull(request.password)
        val encodedPassword = requireNotNull(passwordEncoder.encode(rawPassword)) {
            "Password encoder returned null hash"
        }

        if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw IllegalArgumentException("User with email '$normalizedEmail' already exists")
        }

        val savedUser = userRepository.save(
            User(
                username = normalizedUsername,
                email = normalizedEmail,
                passwordHash = encodedPassword,
            )
        )

        emailVerificationService.issueCodeForUser(savedUser)

        return CreateUserResponse(
            id = checkNotNull(savedUser.id),
            username = savedUser.username,
            email = savedUser.email,
            emailVerified = savedUser.emailVerified,
            createdAt = savedUser.createdAt,
        )
    }
}
