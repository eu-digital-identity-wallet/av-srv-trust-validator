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
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.RefreshableTrustedList
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.TrustedList
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.TrustedListException
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.spi.client.http.DSSFileLoader
import kotlinx.coroutines.test.runTest
import org.springframework.core.io.ClassPathResource
import java.net.URI
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Uses a copy of the AV Trusted List published in the acceptance environment (sequence number 19).
 * Its signing certificate expires on 2028-11-20; the fixture has to be renewed by then.
 */
class TLSourcesTest {

    private val clock = object : Clock {
        override fun now(): Instant = Instant.parse("2026-10-12T00:00:00Z")
    }

    private val tlXml = ClassPathResource("av-tl/av-tl.xml").contentAsByteArray

    private fun tlConfiguration(signerKeyStore: String = "tl.jks") = TLConfigurationProperties(
        location = URL(TL_URL),
        signatureVerification = KeyStoreConfigurationProperties(ClassPathResource(signerKeyStore), password = Password("password")),
        issuanceService = URI("http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa"),
        trustedServiceStatuses = listOf(URI("http://trust.tech.ec.europa.eu/lists/age-verification/service-status/recognized")),
    )

    private fun load(
        content: ByteArray = tlXml,
        configuration: TLConfigurationProperties = tlConfiguration(),
        clock: Clock = this.clock,
    ): TrustedList = loadTrustedList(configuration.tlSource(configuration.issuanceService), loaderOf(content), clock)

    @Test
    fun `a Trusted List with a valid signature is loaded`() {
        val trustedList = load()

        assertEquals(19, trustedList.sequenceNumber)
        assertEquals(Instant.parse("2026-10-08T11:16:58Z"), trustedList.issueDate)
        assertEquals(Instant.parse("2027-04-07T11:16:58Z"), trustedList.nextUpdate)
    }

    @Test
    fun `the certificate of the Age Verification Reference Implementation is a trust anchor`() {
        val fingerprints = load().trustAnchors.map { it.trustedCert.sha256() }

        assertContains(fingerprints, REFERENCE_IMPLEMENTATION_ISSUER_CA)
    }

    @Test
    fun `only services with a trusted status are trust anchors`() {
        val fingerprints = load().trustAnchors.map { it.trustedCert.sha256() }

        assertEquals(12, fingerprints.size)
        assertTrue(DEPRECATED_SERVICE !in fingerprints)
    }

    @Test
    fun `a tampered Trusted List is rejected`() {
        val tampered = String(tlXml).replaceFirst("Age Verification Reference Implementation", "Age Verification Rogue Implementation")

        val error = assertFailsWith<TrustedListException> { load(content = tampered.toByteArray()) }
        assertContains(error.message.orEmpty(), "Signature of Trusted List $TL_URL is not valid")
    }

    @Test
    fun `a Trusted List signed by a certificate that is not configured is rejected`() {
        val error = assertFailsWith<TrustedListException> { load(configuration = tlConfiguration("av-tl/lotl-signers.jks")) }
        assertContains(error.message.orEmpty(), "Signature of Trusted List $TL_URL is not valid")
    }

    @Test
    fun `an expired Trusted List is rejected`() {
        val afterNextUpdate = object : Clock {
            override fun now(): Instant = Instant.parse("2027-04-08T00:00:00Z")
        }

        val error = assertFailsWith<TrustedListException> { load(clock = afterNextUpdate) }
        assertContains(error.message.orEmpty(), "has expired")
    }

    @Test
    fun `a chain issued by a listed issuer is trusted`() = runTest {
        val referenceImplementationIssuerCa = load().trustAnchors.map { it.trustedCert }
            .single { it.sha256() == REFERENCE_IMPLEMENTATION_ISSUER_CA }

        val result = trustSources().isChainTrusted(listOf(referenceImplementationIssuerCa), AGE_VERIFICATION)

        assertIs<CertificationChainValidation.Trusted<*>>(result)
    }

    @Test
    fun `a chain signed by a key that is not listed is rejected with a clear error`() = runTest {
        val notListed = KeyStore.getInstance("JKS")
            .apply { ClassPathResource("av-tl/lotl-signers.jks").inputStream.use { load(it, "password".toCharArray()) } }
            .let { it.getCertificate(it.aliases().nextElement()) as X509Certificate }

        val result = trustSources().isChainTrusted(listOf(notListed), AGE_VERIFICATION)

        assertIs<CertificationChainValidation.NotTrusted>(result)
        val message = result.cause.message.orEmpty()
        assertContains(message, "issuer is not listed in Trusted List $TL_URL")
        assertContains(message, "sequence number 19")
    }

    @Test
    fun `a chain is rejected when no valid Trusted List is available`() = runTest {
        val notLoaded = RefreshableTrustedList(TL_URL, { throw TrustedListException("boom") }, clock, 6.hours, 5.minutes)
            .apply { refresh() }

        val result = TLTrustSources(mapOf(AGE_VERIFICATION to notLoaded)).isChainTrusted(emptyList(), AGE_VERIFICATION)

        assertIs<CertificationChainValidation.NotTrusted>(result)
        assertContains(result.cause.message.orEmpty(), "No valid Trusted List available from $TL_URL")
    }

    private fun trustSources(): TLTrustSources {
        val trustedList = RefreshableTrustedList(TL_URL, { load() }, clock, 6.hours, 5.minutes).apply { refresh() }
        return TLTrustSources(mapOf(AGE_VERIFICATION to trustedList))
    }

    private companion object {
        const val TL_URL = "https://acceptance.trust.tech.ec.europa.eu/lists/age-verification/av-tl.xml"
        const val REFERENCE_IMPLEMENTATION_ISSUER_CA = "edacf96827f6dfc280411792a00ab6d002becda099aa7f1e1ada019ba86a08c5"
        const val DEPRECATED_SERVICE = "a8234aa8339797c917286fb74797dc538acbbec6fcccb146b984d494a000a349"
        val AGE_VERIFICATION = VerificationContext.EAA("age-verification")

        fun loaderOf(content: ByteArray) = DSSFileLoader { url ->
            require(url == TL_URL) { "Unexpected URL $url" }
            InMemoryDocument(content)
        }

        @OptIn(ExperimentalStdlibApi::class)
        fun X509Certificate.sha256(): String = MessageDigest.getInstance("SHA-256").digest(encoded).toHexString()
    }
}
