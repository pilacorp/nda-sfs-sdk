package io.pilacorp.didencryption.curve

import java.math.BigInteger

/**
 * Modular big-integer arithmetic over the curve order N.
 * Mirrors curve/math.go.
 */

/** (a + b) mod N */
fun bigIntAdd(a: BigInteger, b: BigInteger): BigInteger =
    a.add(b).mod(Secp256k1.N)

/** (a - b) mod N  (result is always non-negative) */
fun bigIntSub(a: BigInteger, b: BigInteger): BigInteger =
    a.subtract(b).mod(Secp256k1.N)

/** (a * b) mod N */
fun bigIntMul(a: BigInteger, b: BigInteger): BigInteger =
    a.multiply(b).mod(Secp256k1.N)

/** Modular inverse of a mod N */
fun getInvert(a: BigInteger): BigInteger =
    a.modInverse(Secp256k1.N)
