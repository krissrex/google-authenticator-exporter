import { describe, expect, it, vi } from "vitest"
import testQrCodes from "../test-assets/test-qr-codes.json"
import { decodeExportUri, decodeExportUriWithMetadata, logBatchWarning } from "./index.js"

function readVarint(buffer, start) {
    let value = 0n
    let shift = 0n
    let pos = start

    while (true) {
        const byte = buffer[pos++]
        value |= BigInt(byte & 0x7f) << shift

        if ((byte & 0x80) === 0) {
            return [Number(value), pos]
        }

        shift += 7n
    }
}

function corruptFirstAccountNameLength(uri) {
    const data = new URLSearchParams(new URL(uri).search).get("data")
    const payload = Buffer.from(decodeURIComponent(data), "base64")

    const [, afterOuterTag] = readVarint(payload, 0)
    const [, messageStart] = readVarint(payload, afterOuterTag)

    const [, afterSecretTag] = readVarint(payload, messageStart)
    const [secretLength, secretStart] = readVarint(payload, afterSecretTag)
    const nameTagStart = secretStart + secretLength

    const [, afterNameTag] = readVarint(payload, nameTagStart)
    payload[afterNameTag] -= 1

    return `otpauth-migration://offline?data=${encodeURIComponent(payload.toString("base64"))}`
}

describe("Protobuff decoding of QR export data", () => {
    it("Should decode single QR export", () => {
        const export1 = testQrCodes["Google-auth-test-qr.png"]
        const actualAccounts = decodeExportUri(export1)

        expect(actualAccounts).toHaveLength(3)

        expect(actualAccounts[0]).toEqual({
            "algorithm": "SHA1",
            "digits": "SIX",
            "name": "Test account 1",
            "secret": "SGVsbA8h3q2+6A==",
            "totpSecret": "JBSWY3APEHPK3PXI",
            "type": "TOTP",
        })

        expect(actualAccounts[2]).toEqual({
            "algorithm": "SHA1",
            "counter": "1",
            "digits": "SIX",
            "name": "Counter key 1",
            "secret": "AESNbGQvO+MdHw==",
            "totpSecret": "ABCI23DEF456GHI7",
            "type": "HOTP",
        })
    })

    it("Should decode payload exported as 2 QR codes", () => {
        const export1 = testQrCodes["Google-auth-test2-qr1.png"]
        const export2 = testQrCodes["Google-auth-test2-qr2.png"]

        const actualAccounts1 = decodeExportUri(export1)
        const actualAccounts2 = decodeExportUri(export2)

        expect(actualAccounts1).toHaveLength(10)
        expect(actualAccounts2).toHaveLength(2)
    })

    it("Should decode export with SHA512 and 8 digit length code", () => {
        const export1 = testQrCodes["Google-auth-test-sha512-8digit.png"]
        const actualAccounts = decodeExportUri(export1)

        expect(actualAccounts).toHaveLength(1)

        expect(actualAccounts[0]).toEqual({
            "algorithm": "SHA512",
            "digits": "EIGHT",
            "issuer": "TOTPgenerator",
            "name": "TOTPgenerator",
            "secret": "PWPBFOArrFMYoDSB1NZoYx5vGZM=",
            "totpSecret": "HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT",
            "type": "TOTP"
        })
    })

    it("Should recover from malformed string lengths inside an OTP record", () => {
        const corruptedExport = corruptFirstAccountNameLength(testQrCodes["Google-auth-test-qr.png"])
        const actualAccounts = decodeExportUri(corruptedExport)

        expect(actualAccounts[0].name).toBe("Test account 1")
        expect(actualAccounts[0].totpSecret).toBe("JBSWY3APEHPK3PXI")
    })

    it("Should expose metadata for multi-part exports and warn about incomplete batches", () => {
        const export1 = testQrCodes["Google-auth-test2-qr1.png"]
        const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {})

        const actual = decodeExportUriWithMetadata(export1)
        logBatchWarning(actual.metadata)

        expect(actual.accounts).toHaveLength(10)
        expect(actual.metadata.batchSize).toBe(2)
        expect(actual.metadata.batchIndex).toBe(0)
        expect(actual.metadata.currentChunk).toBe(1)
        expect(actual.metadata.isMultiPart).toBe(true)
        expect(actual.metadata.isComplete).toBe(false)
        expect(warnSpy).toHaveBeenCalledTimes(1)

        warnSpy.mockRestore()
    })
})
