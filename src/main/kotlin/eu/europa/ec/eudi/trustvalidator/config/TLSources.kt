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

import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.NonEmptyList
import eu.europa.ec.eudi.etsi1196x2.consultation.SensitiveApi
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainUsingDirectTrustJvm
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainUsingPKIXJvm
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.ConcurrentCacheDataLoader
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.DssOptions
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.RefreshableTrustedList
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.TrustedList
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.TrustedListException
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.or
import eu.europa.esig.dss.spi.client.http.DSSFileLoader
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.TLSource
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy
import org.slf4j.LoggerFactory
import java.net.URI
import java.nio.file.Path
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ExecutorService
import java.util.function.Predicate
import kotlin.time.Clock
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinDuration
import kotlin.time.toKotlinInstant

private val log = LoggerFactory.getLogger("isChainTrustedForContextUsingTL")

/**
 * Trusted Lists (TL) configured as trust sources, per [VerificationContext].
 */
class TLTrustSources(val trustedLists: Map<VerificationContext, RefreshableTrustedList>) {

    @OptIn(SensitiveApi::class)
    private val validateChain =
        ValidateCertificateChainUsingDirectTrustJvm or ValidateCertificateChainUsingPKIXJvm { isRevocationEnabled = false }

    val isChainTrusted: IsChainTrustedForContextF<List<X509Certificate>, VerificationContext, TrustAnchor> =
        IsChainTrustedForContextF { chain, context ->
            val refreshableTrustedList = trustedLists[context] ?: return@IsChainTrustedForContextF null
            val trustedList = refreshableTrustedList.active()
                ?: return@IsChainTrustedForContextF notTrusted(
                    "No valid Trusted List available from ${refreshableTrustedList.url} for VerificationContext $context",
                )
            val trustAnchors = trustedList.trustAnchors.takeIf { it.isNotEmpty() }
                ?: return@IsChainTrustedForContextF notTrusted(
                    "Trusted List $trustedList contains no trust anchors for VerificationContext $context",
                )

            when (val result = validateChain(chain, NonEmptyList(trustAnchors))) {
                is CertificationChainValidation.Trusted -> {
                    log.info("VerificationContext $context: chain trusted using Trusted List $trustedList")
                    result
                }
                is CertificationChainValidation.NotTrusted -> notTrusted(
                    "Certificate chain is not trusted: its issuer is not listed in Trusted List $trustedList " +
                        "for VerificationContext $context (${result.cause.message})",
                    result.cause,
                )
            }
        }

    private fun notTrusted(message: String, cause: Throwable? = null): CertificationChainValidation.NotTrusted {
        log.info(message)
        return CertificationChainValidation.NotTrusted(TrustedListException(message, cause))
    }
}

/**
 * Loads all configured Trusted Lists once, before returning.
 */
fun TrustSourcesConfigurationProperties.tlTrustSources(
    cacheDirectory: Path,
    executorService: ExecutorService,
    clock: Clock,
): TLTrustSources {
    val trustedLists = tlConfigurations().mapValues { (context, configuration) ->
        val (tl, serviceType) = configuration
        log.info("Configured VerificationContext $context using TL ${tl.location}")
        val loader = ConcurrentCacheDataLoader(DssOptions.DefaultHttpLoader, tl.refresh.maxInterval.toKotlinDuration(), cacheDirectory)
        RefreshableTrustedList(
            url = tl.location.toExternalForm(),
            load = { loadTrustedList(tl.tlSource(serviceType), loader, clock, executorService) },
            clock = clock,
            maxRefreshInterval = tl.refresh.maxInterval.toKotlinDuration(),
            retryInterval = tl.refresh.retryInterval.toKotlinDuration(),
        ).apply { refresh() }
    }
    return TLTrustSources(trustedLists)
}

/**
 * Downloads a Trusted List and verifies it can be used.
 *
 * @throws TrustedListException when the Trusted List cannot be downloaded or parsed, its signature is not valid, or it has expired
 */
fun loadTrustedList(
    tlSource: TLSource,
    loader: DSSFileLoader,
    clock: Clock,
    executorService: ExecutorService? = null,
): TrustedList {
    val url = tlSource.url
    val certificateSource = TrustedListsCertificateSource()
    val job = TLValidationJob().apply {
        setTrustedListSources(tlSource)
        setTrustedListCertificateSource(certificateSource)
        setOnlineDataLoader(loader)
        executorService?.let { setExecutorService(it) }
        // Expiration is checked below, against the provided clock
        setSynchronizationStrategy(
            ExpirationAndSignatureCheckStrategy().apply {
                setAcceptInvalidTrustedList(false)
                setAcceptExpiredTrustedList(true)
            },
        )
    }
    job.onlineRefresh()

    val info = job.summary.otherTLInfos.singleOrNull()
        ?: throw TrustedListException("Trusted List $url was not processed")
    listOf("download" to info.downloadCacheInfo, "parsing" to info.parsingCacheInfo, "validation" to info.validationCacheInfo)
        .forEach { (step, record) ->
            if (record.isError || !record.isResultExist) {
                throw TrustedListException("Trusted List $url failed at $step: ${record.exceptionMessage}")
            }
        }

    val validation = info.validationCacheInfo
    if (!validation.isValid) {
        throw TrustedListException(
            "Signature of Trusted List $url is not valid: ${validation.indication}/${validation.subIndication}",
        )
    }

    val now = clock.now()
    val parsing = info.parsingCacheInfo
    val trustedList = TrustedList(
        url = url,
        sequenceNumber = parsing.sequenceNumber,
        issueDate = parsing.issueDate?.toInstant()?.toKotlinInstant(),
        nextUpdate = parsing.nextUpdateDate?.toInstant()?.toKotlinInstant(),
        // Only certificates of services whose status is trusted at this time, according to the trust anchor validity predicate
        trustAnchors = certificateSource.certificates
            .filter { certificateSource.getTrustTime(it)?.isTrustedAtTime(Date.from(now.toJavaInstant())) == true }
            .map { TrustAnchor(it.certificate, null) },
    )
    if (!trustedList.isValidAt(now)) {
        throw TrustedListException("Trusted List $trustedList has expired")
    }
    return trustedList
}

private fun TrustSourcesConfigurationProperties.tlConfigurations(): Map<VerificationContext, Pair<TLConfigurationProperties, URI>> =
    buildMap {
        fun put(context: VerificationContext, tl: TLConfigurationProperties, serviceType: URI) = put(context, tl to serviceType)

        walletProviders?.tl?.let { tl ->
            put(VerificationContext.WalletProviderAttestation, tl, tl.issuanceService)
            tl.revocationService?.let { put(VerificationContext.WalletOrKeyStorageStatus, tl, it) }
        }
        pidProviders?.tl?.let { tl ->
            put(VerificationContext.PID, tl, tl.issuanceService)
            tl.revocationService?.let { put(VerificationContext.PIDStatus, tl, it) }
        }
        qeaaProviders?.tl?.let { tl ->
            put(VerificationContext.QEAA, tl, tl.issuanceService)
            tl.revocationService?.let { put(VerificationContext.QEAAStatus, tl, it) }
        }
        pubEaaProviders?.tl?.let { tl ->
            put(VerificationContext.PubEAA, tl, tl.issuanceService)
            tl.revocationService?.let { put(VerificationContext.PubEAAStatus, tl, it) }
        }
        eaaProviders.orEmpty().forEach { eaaProvider ->
            eaaProvider.tl?.let { tl ->
                put(VerificationContext.EAA(eaaProvider.useCase), tl, tl.issuanceService)
                tl.revocationService?.let { put(VerificationContext.EAAStatus(eaaProvider.useCase), tl, it) }
            }
        }
        wrpacProviders?.tl?.let { tl ->
            put(VerificationContext.WalletRelyingPartyAccessCertificate, tl, tl.issuanceService)
        }
        wrprcProviders?.tl?.let { tl ->
            put(VerificationContext.WalletRelyingPartyRegistrationCertificate, tl, tl.issuanceService)
            tl.revocationService?.let { put(VerificationContext.WalletRelyingPartyRegistrationCertificateStatus, tl, it) }
        }
    }

fun TLConfigurationProperties.tlSource(serviceType: URI): TLSource =
    TLSource().apply {
        url = location.toExternalForm()
        tlVersions = listOf(5, 6)
        trustServicePredicate = { serviceType.toString() == it.serviceInformation.serviceTypeIdentifier }
        trustAnchorValidityPredicate = trustedServiceStatuses
            ?.map { it.toString() }
            ?.let { statuses -> Predicate { it.status in statuses } }
            ?: GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
        certificateSource = signatureVerification.location.inputStream.use {
            KeyStoreCertificateSource(
                it,
                signatureVerification.keyStoreType,
                (signatureVerification.password?.value ?: "").toCharArray(),
            )
        }
    }
