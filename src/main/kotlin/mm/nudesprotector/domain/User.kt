package mm.nudesprotector.domain

import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import java.time.Instant
import java.util.UUID

@Table(name = "users")
data class User(
    @Id
    val id: UUID? = null,
    val username: String,
    val email: String,
    @Column("password_hash")
    val passwordHash: String,
    @Column("email_verified")
    val emailVerified: Boolean = false,
    @Column("created_at")
    val createdAt: Instant = Instant.now(),
)
