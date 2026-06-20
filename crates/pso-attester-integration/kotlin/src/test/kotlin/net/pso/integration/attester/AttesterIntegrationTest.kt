package net.pso.integration.attester

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Functional tests for the attester UniFFI surface, driven through the
 * generated Kotlin bindings + the bundled native lib (the same path a real
 * JVM consumer hits). Mirrors the Rust `#[cfg(test)]` FFI tests in
 * `pso-attester-integration/src/lib.rs` across the JNI boundary, so a binding
 * regression (wrong type mapping, missing symbol, bad marshalling) fails here.
 */
class AttesterIntegrationTest {

    init {
        // Extract + System.load the bundled native slice and point UniFFI's
        // JNA loader at it before any binding call.
        NativeLoader.ensureLoaded()
    }

    private fun seed(tag: Int) = ByteArray(32) { tag.toByte() }

    /** A canonical field-element fingerprint (small ⇒ < modulus). */
    private fun fp(tag: Int) = ByteArray(32).also { it[31] = tag.toByte() }

    private fun addr() = ByteArray(20) { 0xAB.toByte() }

    // A valid consent public key (`sk·G`, compressed Grumpkin point) — pinned
    // vector from the Rust `print_consent_pk_vector` test (sk = 7). The FFI
    // validates it as an on-curve point, so it can't be arbitrary bytes.
    private val consentPk =
        "42289b7b06a8330ae61d9a628f7a182a9c3fdd9a067fa139d0e8a3d69d2b600e"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun `NativeLoader loads the bundled host slice`() {
        NativeLoader.ensureLoaded()
    }

    @Test
    fun `new rejects a wrong-length address`() {
        assertFailsWith<AttesterException> { Attester(ByteArray(19)) }
    }

    @Test
    fun `generateNftHeader rejects a bad consent_pk`() {
        val attester = Attester(addr())
        assertFailsWith<AttesterException> {
            attester.generateNftHeader(seed(1), ByteArray(32) { 0xFF.toByte() })
        }
    }

    @Test
    fun `generateNftHeader is deterministic per seed`() {
        val attester = Attester(addr())
        val h1 = attester.generateNftHeader(seed(9), consentPk)
        val h2 = attester.generateNftHeader(seed(9), consentPk)
        assertContentEquals(h1.nftId, h2.nftId)
        assertContentEquals(h1.derivedOwner, h2.derivedOwner)
        assertEquals(32, h1.derivedOwner.size)
        val h3 = attester.generateNftHeader(seed(10), consentPk)
        assertTrue(!h1.nftId.contentEquals(h3.nftId), "distinct seeds ⇒ distinct id")
    }

    @Test
    fun `issue round-trips identity, reissue reuses it with a fresh hash`() {
        val attester = Attester(addr())
        val header = attester.generateNftHeader(seed(3), consentPk)

        val issued = attester.issueWithHeader(
            header, 20_250_101u, 978.toUShort(), 100uL, 0uL,
            ByteArray(20), listOf(fp(1), fp(2)), listOf(fp(3)),
        )
        // The on-chain SU mirrors the inputs + the header identity.
        assertContentEquals(header.nftId, issued.spendingUnit.suId)
        assertContentEquals(header.derivedOwner, issued.spendingUnit.derivedOwner)
        assertContentEquals(addr(), issued.spendingUnit.attester)
        assertEquals(978.toUShort(), issued.spendingUnit.currency)
        assertContentEquals(header.derivedOwner, issued.report.derivedOwner)
        assertEquals(32, issued.report.nftHash.size)
        assertTrue(issued.report.nftHash.any { it.toInt() != 0 }, "nft_hash non-zero")

        // Reuse the SAME header with different records: identity preserved,
        // nft_hash changes (sr/ar fold in).
        val reissued = attester.issueWithHeader(
            header, 20_250_101u, 978.toUShort(), 100uL, 0uL,
            ByteArray(20), listOf(fp(4)), emptyList(),
        )
        assertContentEquals(issued.spendingUnit.suId, reissued.spendingUnit.suId)
        assertContentEquals(issued.report.derivedOwner, reissued.report.derivedOwner)
        assertTrue(
            !issued.report.nftHash.contentEquals(reissued.report.nftHash),
            "different records ⇒ different nft_hash",
        )
    }

    @Test
    fun `issue rejects a non-canonical fingerprint`() {
        val attester = Attester(addr())
        val header = attester.generateNftHeader(seed(5), consentPk)
        assertFailsWith<AttesterException> {
            attester.issueWithHeader(
                header, 20_250_101u, 978.toUShort(), 100uL, 0uL,
                ByteArray(20), listOf(ByteArray(32) { 0xFF.toByte() }), emptyList(),
            )
        }
    }
}
