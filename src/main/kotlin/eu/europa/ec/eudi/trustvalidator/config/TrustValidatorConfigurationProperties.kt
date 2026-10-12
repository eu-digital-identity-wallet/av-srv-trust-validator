/*
 * Copyright (c) 2025-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.trustvalidator.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource
import java.net.URI
import java.net.URL
import java.nio.file.Path
import java.time.Duration

@ConfigurationProperties("trust-validator")
data class TrustValidatorConfigurationProperties(
    val dss: DSSConfigurationProperties,
    val lote: LoteCacheConfigurationProperties,
    val trustSources: TrustSourcesConfigurationProperties? = null,
)

data class DSSConfigurationProperties(
    val cacheLocation: Path,
)

data class LoteCacheConfigurationProperties(
    val cacheLocation: Path,
)

data class TrustSourcesConfigurationProperties(
    val walletProviders: TrustedListsConfigurationProperties? = null,
    val pidProviders: TrustedListsConfigurationProperties? = null,
    val qeaaProviders: TrustedListsConfigurationProperties? = null,
    val pubEaaProviders: TrustedListsConfigurationProperties? = null,
    val eaaProviders: List<EAALoTLConfigurationProperties>? = null,
    val wrpacProviders: TrustedListsConfigurationProperties? = null,
    val wrprcProviders: TrustedListsConfigurationProperties? = null,
    val keyStore: KeyStoreConfigurationProperties? = null,
)

data class TrustedListsConfigurationProperties(
    val lotl: LoTLConfigurationProperties? = null,
    val lote: LoTEConfigurationProperties? = null,
    val tl: TLConfigurationProperties? = null,
)

data class LoTLConfigurationProperties(
    val location: URL,
    val signatureVerification: KeyStoreConfigurationProperties? = null,
    val issuanceService: URI,
    val revocationService: URI,
)

data class LoTEConfigurationProperties(
    val location: URL,
    val issuanceService: URI,
    val revocationService: URI,
)

data class TLConfigurationProperties(
    val location: URL,
    val signatureVerification: KeyStoreConfigurationProperties,
    val issuanceService: URI,
    val revocationService: URI? = null,
    /**
     * Service statuses for which a service is used as a trust anchor.
     * When not set, services that are granted or recognised at national level (eIDAS) are used.
     */
    val trustedServiceStatuses: List<URI>? = null,
    val refresh: TLRefreshConfigurationProperties = TLRefreshConfigurationProperties(),
)

data class TLRefreshConfigurationProperties(
    /**
     * Upper bound for the time between two refreshes. The Trusted List is refreshed earlier, when its next update is due.
     */
    val maxInterval: Duration = Duration.ofHours(6),
    /**
     * Time to wait before retrying a failed refresh.
     */
    val retryInterval: Duration = Duration.ofMinutes(5),
)

data class KeyStoreConfigurationProperties(
    val location: Resource,
    val keyStoreType: String = "JKS",
    val password: Password? = null,
) {
    init {
        require(location.exists() && location.isFile && location.isReadable) {
            "location must point to an existing readable file"
        }
    }
}

@JvmInline
value class Password(val value: String) {
    override fun toString(): String = "Password(REDACTED)"
}

data class EAALoTLConfigurationProperties(
    val useCase: String,
    val lotl: LoTLConfigurationProperties? = null,
    val lote: LoTEConfigurationProperties? = null,
    val tl: TLConfigurationProperties? = null,
)
