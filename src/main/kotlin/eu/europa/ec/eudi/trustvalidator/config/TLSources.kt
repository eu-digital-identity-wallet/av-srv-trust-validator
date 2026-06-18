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

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.SensitiveApi
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainUsingDirectTrustJvm
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainUsingPKIXJvm
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.ConcurrentCacheDataLoader
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.DssOptions
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.or
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.TLSource
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.URL
import java.nio.file.Path
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import kotlin.time.Duration.Companion.hours
import eu.europa.ec.eudi.etsi1196x2.consultation.NonEmptyList as ConsultationNonEmptyList

private val log = LoggerFactory.getLogger("isChainTrustedForContextUsingTL")

@OptIn(SensitiveApi::class)
fun TrustSourcesConfigurationProperties.isChainTrustedForContextUsingTL(
    cacheDirectory: Path,
    executorService: ExecutorService,
): IsChainTrustedForContextF<List<X509Certificate>, VerificationContext, TrustAnchor>? {
    val sources = tlSources()
    if (sources.isEmpty()) return null

    log.info(sources)

    val loader = ConcurrentCacheDataLoader(DssOptions.DefaultHttpLoader, 24.hours, cacheDirectory)

    // Group by TLSource identity so that the same TL URL is only downloaded once
    // per unique (url, signatureVerification, predicate) combination.
    val tlSourceToCertSource: Map<TLSource, TrustedListsCertificateSource> =
        sources.values.distinct().associateWith { tlSource ->
            TrustedListsCertificateSource().also { certSource ->
                TLValidationJob().apply {
                    setTrustedListSources(tlSource)
                    setTrustedListCertificateSource(certSource)
                    setOnlineDataLoader(loader)
                    setExecutorService(executorService)
                }.onlineRefresh()
            }
        }

    val contextToCertSource: Map<VerificationContext, TrustedListsCertificateSource> =
        sources.mapValues { (_, tlSource) -> tlSourceToCertSource.getValue(tlSource) }

    val validateChain =
        ValidateCertificateChainUsingDirectTrustJvm or ValidateCertificateChainUsingPKIXJvm { isRevocationEnabled = false }

    return IsChainTrustedForContextF { chain, context ->
        val certSource = contextToCertSource[context] ?: return@IsChainTrustedForContextF null
        val trustAnchors: NonEmptyList<TrustAnchor> =
            certSource.getCertificates()
                .map { TrustAnchor(it.certificate, null) }
                .toNonEmptyListOrNull()
                ?: return@IsChainTrustedForContextF CertificationChainValidation.NotTrusted(
                    IllegalStateException("No trust anchors found in TL for context $context"),
                )
        validateChain(chain, ConsultationNonEmptyList(trustAnchors.toList()))
    }
}

private fun TrustSourcesConfigurationProperties.tlSources(): Map<VerificationContext, TLSource> =
    buildMap {
        walletProviders?.tl?.let { tl ->
            put(VerificationContext.WalletProviderAttestation, tl.issuanceTLSource())
            tl.revocationService?.let { put(VerificationContext.WalletOrKeyStorageStatus, tl.revocationTLSource(it)) }
        }
        pidProviders?.tl?.let { tl ->
            put(VerificationContext.PID, tl.issuanceTLSource())
            tl.revocationService?.let { put(VerificationContext.PIDStatus, tl.revocationTLSource(it)) }
        }
        qeaaProviders?.tl?.let { tl ->
            put(VerificationContext.QEAA, tl.issuanceTLSource())
            tl.revocationService?.let { put(VerificationContext.QEAAStatus, tl.revocationTLSource(it)) }
        }
        pubEaaProviders?.tl?.let { tl ->
            put(VerificationContext.PubEAA, tl.issuanceTLSource())
            tl.revocationService?.let { put(VerificationContext.PubEAAStatus, tl.revocationTLSource(it)) }
        }
        eaaProviders.orEmpty().forEach { eaaProvider ->
            eaaProvider.tl?.let { tl ->
                put(VerificationContext.EAA(eaaProvider.useCase), tl.issuanceTLSource())
                tl.revocationService?.let { put(VerificationContext.EAAStatus(eaaProvider.useCase), tl.revocationTLSource(it)) }
            }
        }
        wrpacProviders?.tl?.let { tl ->
            put(VerificationContext.WalletRelyingPartyAccessCertificate, tl.issuanceTLSource())
        }
        wrprcProviders?.tl?.let { tl ->
            put(VerificationContext.WalletRelyingPartyRegistrationCertificate, tl.issuanceTLSource())
            tl.revocationService?.let {
                put(
                    VerificationContext.WalletRelyingPartyRegistrationCertificateStatus,
                    tl.revocationTLSource(it),
                )
            }
        }
    }

private fun TLConfigurationProperties.issuanceTLSource(): TLSource =
    tlSourceOf(location, signatureVerification, issuanceService)

private fun TLConfigurationProperties.revocationTLSource(revocationService: URI): TLSource =
    tlSourceOf(location, signatureVerification, revocationService)

private fun tlSourceOf(
    location: URL,
    signatureVerificationKeyStore: KeyStoreConfigurationProperties?,
    serviceType: URI,
): TLSource =
    TLSource().apply {
        url = location.toExternalForm()
        trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
        tlVersions = listOf(5, 6)
        trustServicePredicate = { serviceType.toString() == it.serviceInformation.serviceTypeIdentifier }
        if (null != signatureVerificationKeyStore) {
            certificateSource = signatureVerificationKeyStore.location.inputStream.use {
                KeyStoreCertificateSource(
                    it,
                    signatureVerificationKeyStore.keyStoreType,
                    (signatureVerificationKeyStore.password?.value ?: "").toCharArray(),
                )
            }
        }
    }

private fun Logger.info(tlSources: Map<VerificationContext, TLSource>) {
    tlSources.entries.forEach { (context, tl) ->
        info("Configured VerificationContext $context using TL ${tl.url}")
    }
}
