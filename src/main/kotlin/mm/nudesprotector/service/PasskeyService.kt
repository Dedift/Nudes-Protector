package mm.nudesprotector.service

import mm.nudesprotector.domain.dto.response.PasskeyResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.webauthn.api.Bytes
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository
import org.springframework.security.web.webauthn.management.UserCredentialRepository
import org.springframework.stereotype.Service

@Service
class PasskeyService(
    private val userEntityRepository: PublicKeyCredentialUserEntityRepository,
    private val userCredentialRepository: UserCredentialRepository,
) {
    fun listPasskeys(username: String): List<PasskeyResponse> {
        val userEntity = userEntityRepository.findByUsername(username)
            ?: return emptyList()

        return userCredentialRepository.findByUserId(userEntity.id)
            .sortedByDescending { it.created }
            .map {
                PasskeyResponse(
                    id = it.credentialId.toBase64UrlString(),
                    label = it.label,
                    createdAt = it.created,
                    lastUsedAt = it.lastUsed,
                    transports = it.transports.map { transport -> transport.value }.toSet(),
                )
            }
    }

    fun deletePasskey(username: String, credentialId: String) {
        val userEntity = userEntityRepository.findByUsername(username)
            ?: throw IllegalArgumentException("Passkey not found")
        val storedCredential = userCredentialRepository.findByCredentialId(Bytes.fromBase64(credentialId))
            ?: throw IllegalArgumentException("Passkey not found")

        if (storedCredential.userEntityUserId != userEntity.id) {
            throw AccessDeniedException("Passkey does not belong to the current user")
        }

        userCredentialRepository.delete(storedCredential.credentialId)
    }
}
