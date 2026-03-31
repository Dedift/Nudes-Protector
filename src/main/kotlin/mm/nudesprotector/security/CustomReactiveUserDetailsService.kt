package mm.nudesprotector.security

import mm.nudesprotector.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class CustomReactiveUserDetailsService(
    private val userRepository: UserRepository,
    private val loginAttemptService: LoginAttemptService,
) : ReactiveUserDetailsService {
    override fun findByUsername(username: String): Mono<UserDetails> {
        val normalizedEmail = username.trim()

        return userRepository.findByEmailIgnoreCase(normalizedEmail)
            .switchIfEmpty(Mono.error(UsernameNotFoundException(username)))
            .flatMap { user ->
                loginAttemptService.isLocked(user.email)
                    .map { locked ->
                        User.builder()
                            .username(user.email)
                            .password(user.passwordHash)
                            .authorities(SimpleGrantedAuthority("ROLE_USER"))
                            .disabled(!user.emailVerified)
                            .accountLocked(locked)
                            .build()
                    }
            }
    }
}
