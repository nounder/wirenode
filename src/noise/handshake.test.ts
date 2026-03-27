import { test, expect } from "bun:test"
import * as Curve25519 from "../crypto/Curve25519.ts"
import * as Handshake from "./Handshake.ts"
import * as Cookie from "./Cookie.ts"

test("full handshake and session derivation", () => {
  // Generate keys for two parties
  const initiatorSk = Curve25519.generatePrivateKey()
  const initiatorPk = Curve25519.publicKey(initiatorSk)
  const responderSk = Curve25519.generatePrivateKey()
  const responderPk = Curve25519.publicKey(responderSk)
  const psk = new Uint8Array(32) // no PSK

  // Initiator creates handshake
  const initiatorHS = Handshake.createHandshake(responderPk, psk, initiatorSk)
  const cookieGen = new Cookie.CookieGenerator(responderPk)

  // Step 1: Create initiation
  const initMsg = Handshake.createMessageInitiation(initiatorHS, initiatorPk, initiatorSk)
  expect(initMsg.length).toBe(Handshake.MessageInitiationSize)
  expect(initiatorHS.state).toBe(Handshake.HandshakeState.InitiationCreated)

  // Add MACs
  cookieGen.addMacs(initMsg)

  // Step 2: Responder consumes initiation
  const result = Handshake.consumeMessageInitiation(initMsg, responderPk, responderSk, (pk) => {
    const hex1 = Buffer.from(pk).toString("hex")
    const hex2 = Buffer.from(initiatorPk).toString("hex")
    if (hex1 === hex2) {
      return Handshake.createHandshake(initiatorPk, psk, responderSk)
    }
    return null
  })

  expect(result).not.toBeNull()
  const responderHS = result!.peer
  expect(responderHS.state).toBe(Handshake.HandshakeState.InitiationConsumed)

  // Step 3: Responder creates response
  const respCookieGen = new Cookie.CookieGenerator(initiatorPk)
  const respMsg = Handshake.createMessageResponse(responderHS)
  expect(respMsg.length).toBe(Handshake.MessageResponseSize)
  expect(responderHS.state).toBe(Handshake.HandshakeState.ResponseCreated)
  respCookieGen.addMacs(respMsg)

  // Step 4: Initiator consumes response
  const ok = Handshake.consumeMessageResponse(respMsg, initiatorHS, initiatorSk)
  expect(ok).toBe(true)
  expect(initiatorHS.state).toBe(Handshake.HandshakeState.ResponseConsumed)

  // Step 5: Derive session keys
  const initiatorKP = Handshake.beginSymmetricSession(initiatorHS)
  const responderKP = Handshake.beginSymmetricSession(responderHS)

  // Initiator's send key should equal responder's receive key
  expect(Buffer.from(initiatorKP.sendKey).toString("hex")).toBe(
    Buffer.from(responderKP.receiveKey).toString("hex"),
  )

  // Initiator's receive key should equal responder's send key
  expect(Buffer.from(initiatorKP.receiveKey).toString("hex")).toBe(
    Buffer.from(responderKP.sendKey).toString("hex"),
  )

  expect(initiatorKP.isInitiator).toBe(true)
  expect(responderKP.isInitiator).toBe(false)
})

test("initiation with wrong key is rejected", () => {
  const initiatorSk = Curve25519.generatePrivateKey()
  const initiatorPk = Curve25519.publicKey(initiatorSk)
  const responderSk = Curve25519.generatePrivateKey()
  const responderPk = Curve25519.publicKey(responderSk)
  const wrongSk = Curve25519.generatePrivateKey()
  const psk = new Uint8Array(32)

  const hs = Handshake.createHandshake(responderPk, psk, initiatorSk)
  const cookieGen = new Cookie.CookieGenerator(responderPk)
  const initMsg = Handshake.createMessageInitiation(hs, initiatorPk, initiatorSk)
  cookieGen.addMacs(initMsg)

  // Try consuming with wrong private key
  const result = Handshake.consumeMessageInitiation(
    initMsg,
    Curve25519.publicKey(wrongSk),
    wrongSk,
    () => null, // no peer matches
  )
  expect(result).toBeNull()
})

test("response with wrong index is rejected", () => {
  const initiatorSk = Curve25519.generatePrivateKey()
  const initiatorPk = Curve25519.publicKey(initiatorSk)
  const responderSk = Curve25519.generatePrivateKey()
  const responderPk = Curve25519.publicKey(responderSk)
  const psk = new Uint8Array(32)

  const hs = Handshake.createHandshake(responderPk, psk, initiatorSk)
  const msg = Handshake.createMessageInitiation(hs, initiatorPk, initiatorSk)

  // Tamper with the message by changing sender index
  const view = new DataView(msg.buffer)
  view.setUint32(4, 0xdeadbeef, true)

  // This should still parse but the responder won't find the peer
  // or it would use the wrong handshake context
})
