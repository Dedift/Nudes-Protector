package mm.nudesprotector.security

import mm.nudesprotector.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class CustomUserDetailsService(
    private val userRepository: UserRepository,
    private val loginAttemptService: LoginAttemptService,
) : UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails {
        val normalizedEmail = username.trim()
        val user = userRepository.findByEmailIgnoreCase(normalizedEmail)
            ?: throw UsernameNotFoundException(username)
        val locked = loginAttemptService.isLocked(user.email)

        return User.builder()
            .username(user.email)
            .password(user.passwordHash)
            .authorities(SimpleGrantedAuthority("ROLE_USER"))
            .disabled(!user.emailVerified)
            .accountLocked(locked)
            .build()
    }
}
