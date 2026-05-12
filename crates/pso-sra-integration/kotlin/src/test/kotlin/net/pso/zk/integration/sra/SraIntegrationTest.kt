package net.pso.zk.integration.sra

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SraIntegrationTest {

    companion object {
        // Helper: Convert a 32-byte scalar to SEC1 DER format
        private fun scalarToSec1Der(scalar: ByteArray): ByteArray {
            require(scalar.size == 32) { "Scalar must be 32 bytes" }
            // Minimal SEC1 DER:
            // 30 25           -- SEQUENCE, 37 bytes
            //   02 01 01      -- INTEGER version 1
            //   04 20         -- OCTET STRING, 32 bytes
            //     [32 bytes of scalar]
            val der = ByteArray(39)
            var index = 0
            der[index++] = 0x30               // SEQUENCE tag
            der[index++] = 37                 // Length: 37 bytes
            der[index++] = 0x02               // INTEGER tag
            der[index++] = 0x01               // Length: 1 byte
            der[index++] = 0x01               // Version: 1
            der[index++] = 0x04               // OCTET STRING tag
            der[index++] = 0x20               // Length: 32 bytes
            System.arraycopy(scalar, 0, der, index, 32)
            return der
        }

        private val SRA_SK_RAW = ByteArray(32) { 0x01 }

        // Create SEC1 DER encoded key from raw scalar bytes
        private val SRA_SK = scalarToSec1Der(SRA_SK_RAW)

        private val CONSENT_PK = hexToBytes(
            "041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1"
        )
        private val NONCE = ByteArray(32) { 0x2a }

        private const val EXPECTED_NONCE = "3qbR1eZRqXUWroWKKYhbDmR3FfqTHfqSU8zZSxtANzYh"
        private const val EXPECTED_OWNERSHIP = "UhZHAW9tEdWgNuhpG97MkjR11zk4YQn1R4QGdhExH4s"

        private fun hexToBytes(hex: String): ByteArray {
            return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        init {
            NativeLoader.load()
        }
    }

    @Test
    fun `should match Rust output when given fixed nonce`() {
        val result = generateNftOwnershipWithNonce(SRA_SK, CONSENT_PK, NONCE)

        assertEquals(EXPECTED_NONCE, result.nonce)
        assertEquals(EXPECTED_OWNERSHIP, result.ownership)
    }

    @Test
    fun `should be reproducible when given same inputs`() {
        val result1 = generateNftOwnershipWithNonce(SRA_SK, CONSENT_PK, NONCE)
        val result2 = generateNftOwnershipWithNonce(SRA_SK, CONSENT_PK, NONCE)

        assertEquals(result1.nonce, result2.nonce)
        assertEquals(result1.ownership, result2.ownership)
    }

    @Test
    fun `should match uncompressed result when given compressed key`() {
        val compressedPk = hexToBytes(
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
        )

        val resultUncompressed = generateNftOwnershipWithNonce(SRA_SK, CONSENT_PK, NONCE)
        val resultCompressed = generateNftOwnershipWithNonce(SRA_SK, compressedPk, NONCE)

        assertEquals(resultUncompressed.nonce, resultCompressed.nonce)
        assertEquals(resultUncompressed.ownership, resultCompressed.ownership)
    }

    @Test
    fun `should return non-empty strings when given random nonce`() {
        val result = generateNftOwnership(SRA_SK, CONSENT_PK)

        assertTrue(result.nonce.isNotEmpty())
        assertTrue(result.ownership.isNotEmpty())
    }

    @Test
    fun `should match DER result when given raw 32-byte key`() {
        val resultDer = generateNftOwnershipWithNonce(SRA_SK, CONSENT_PK, NONCE)
        val resultRaw = generateNftOwnershipWithNonce(SRA_SK_RAW, CONSENT_PK, NONCE)

        assertEquals(resultDer.nonce, resultRaw.nonce)
        assertEquals(resultDer.ownership, resultRaw.ownership)
    }

    @Test
    fun `should throw OwnershipException when given invalid secret key`() {
        assertFailsWith<OwnershipException> {
            generateNftOwnership(ByteArray(16), CONSENT_PK)
        }
    }

    @Test
    fun `should throw OwnershipException when given invalid public key`() {
        assertFailsWith<OwnershipException> {
            generateNftOwnership(SRA_SK, ByteArray(10))
        }
    }
}
