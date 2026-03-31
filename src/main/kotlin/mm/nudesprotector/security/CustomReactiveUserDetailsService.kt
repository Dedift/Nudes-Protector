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
) : ReactiveUserDetailsService {
    override fun findByUsername(username: String): Mono<UserDetails> {
        return userRepository.findByEmailIgnoreCase(username.trim().lowercase())
            .switchIfEmpty(Mono.error(UsernameNotFoundException(username)))
            .map { user -> User.builder()
                .username(user.email)
                .password(user.passwordHash)
                .authorities(SimpleGrantedAuthority("ROLE_USER"))
                .disabled(!user.emailVerified)
                .build() }
    }
}