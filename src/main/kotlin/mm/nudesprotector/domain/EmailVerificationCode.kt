package mm.nudesprotector.domain

import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import java.time.Instant
import java.util.UUID

@Table(name = "email_verification_codes")
data class EmailVerificationCode(
    @Id
    val id: UUID? = null,
    @Column("user_id")
    val userId: UUID,
    val code: String,
    @Column("expires_at")
    val expiresAt: Instant,
    @Column("created_at")
    val createdAt: Instant = Instant.now(),
)
