import {
  NetworkId,
} from "@blaze-cardano/core";

import {
  fromHex,
  stringify,
} from "./util.js";

class Decoder {
  public bytes: Buffer;
  public ptr: number;
  public constructor(bytes: Buffer) {
    this.bytes = bytes;
    this.ptr = 0;
  }
  public peek(): bigint {
    if (this.bytes.length <= this.ptr) {
      throw new Error("reached end of input");
    }
    let b = BigInt(this.bytes[this.ptr]);
    return b;
  }
  public readUInt8(): bigint {
    if (this.bytes.length <= this.ptr) {
      throw new Error("reached end of input");
    }
    let b = BigInt(this.bytes[this.ptr]);
    this.ptr += 1;
    return b;
  }
  public readBytes(n: bigint): Buffer {
    if (this.bytes.length <= this.ptr + Number(n)) {
      throw new Error("reached end of input");
    }
    let slice = this.bytes.subarray(this.ptr, this.ptr + Number(n));
    this.ptr += Number(n);
    return slice;
  }
  public state() {
    return JSON.stringify({
      bytes: this.bytes.toString('hex'),
      ptr: this.ptr,
    });
  }
};

export function decoder(bytes: Buffer) {
  return new Decoder(bytes);
}

function decodeTag(d: Decoder) {
  let tag = d.readUInt8();
  if (tag == 0xd8n) {
    let n = d.readUInt8();
    return n;
  } else if (tag == 0xd9n) {
    let upper = d.readUInt8();
    let lower = d.readUInt8();
    return upper * BigInt(256) + lower;
  } else if (tag == 0xdan) {
    let w = d.readUInt8();
    let x = d.readUInt8();
    let y = d.readUInt8();
    let z = d.readUInt8();
    return w * BigInt(0x1000000) + x * BigInt(0x10000) + y * BigInt(0x100) + z;
  } else if (tag == 0xdbn) {
    throw new Error("decodeTag: todo");
  } else {
    throw new Error("decodeTag: not a tag: " + tag);
  }
}

function decodeBeginArray(d: Decoder) {
  let b = d.readUInt8();
  if (b >= 0x80n && b < 0x98n) {
    return b - 0x80n;
  } else if (b == 0x98n) {
    let n = d.readUInt8();
    return n;
  } else {
    console.log(d.state());
    throw new Error("decodeBeginArray: todo");
  }
}

function decodeBeginIndefiniteArray(d: Decoder) {
  let b = d.readUInt8();
  if (b == 0x9fn) {
    return;
  } else {
    throw new Error("decodeBeginIndefiniteArray: not an indefinite array: " + b);
  }
}

function decodeEmptyArray(d: Decoder) {
  let b = d.readUInt8();
  if (b == 0x80n) {
    return;
  } else {
    throw new Error("decodeEmptyArray: expected 0x80");
  }
}

function decodeBreak(d: Decoder) {
  let b = d.readUInt8();
  if (b == 0xffn) {
    return;
  } else {
    throw new Error("decodeBreak: not a break: " + b);
  }
}

function decodeByteArray(d: Decoder) {
  let b = d.readUInt8();
  if (b >= 0x40n && b < 0x58n) {
    return d.readBytes(b - BigInt(0x40));
  } else if (b == 0x58n) {
    let n = d.readUInt8();
    return d.readBytes(n);
  } else if (b == 0x59n) {
    let upper = d.readUInt8();
    let lower = d.readUInt8();
    return d.readBytes(upper * BigInt(256) + lower);
  } else if (b == 0x5an || b == 0x5bn) {
    throw new Error("decodeByteArray: todo");
  } else {
    console.log(d.state());
    throw new Error("decodeByteArray: not a byte array: " + b);
  }
}

function decodeAssetClass(d: Decoder): [Buffer, Buffer] {
  let _ = decodeBeginIndefiniteArray(d);
  let policy = decodeByteArray(d);
  let token = decodeByteArray(d);
  decodeBreak(d);
  return [policy, token];
}

function decodeAssetPair(d: Decoder): [AssetClass, AssetClass] {
  let _ = decodeBeginIndefiniteArray(d);
  let a = decodeAssetClass(d);
  let b = decodeAssetClass(d);
  decodeBreak(d);
  return [a, b];
}

function decodeInteger(d: Decoder) {
  let sz = d.readUInt8();
  if (sz < 0x18n) {
    return sz;
  } else if (sz == 0x18n) {
    let n = d.readUInt8();
    return n;
  } else if (sz == 0x19n) {
    let a = d.readUInt8();
    let b = d.readUInt8();
    return a * BigInt(256) + b;
  } else if (sz == 0x1an) {
    let w = d.readUInt8();
    let x = d.readUInt8();
    let y = d.readUInt8();
    let z = d.readUInt8();
    return w * BigInt(0x1000000) + x * BigInt(0x10000) + y * BigInt(0x100) + z;
  } else if (sz == 0x1bn) {
    let s = d.readUInt8();
    let t = d.readUInt8();
    let u = d.readUInt8();
    let v = d.readUInt8();
    let w = d.readUInt8();
    let x = d.readUInt8();
    let y = d.readUInt8();
    let z = d.readUInt8();
    return s * BigInt(0x100000000000000) +
      t * BigInt(0x1000000000000) +
      u * BigInt(0x10000000000) +
      v * BigInt(0x100000000) +
      w * BigInt(0x1000000) +
      x * BigInt(0x10000) +
      y * BigInt(0x100) +
      z;
    //throw new Error("decodeInteger: todo");
  } else {
    throw new Error("decodeInteger: not an integer: " + sz);
  }
}

export type Multisig = MultisigSignature | MultisigAtLeast | MultisigScript | MultisigBefore | MultisigAfter | MultisigAllOf | MultisigAnyOf

export interface MultisigSignature {
  tag: "Signature",
  keyHash: Buffer,
}

export interface MultisigAtLeast {
  tag: "AtLeast",
  required: bigint,
  scripts: Multisig[],
}

export interface MultisigBefore {
  tag: "Before",
  time: bigint,
}

export interface MultisigAfter {
  tag: "After",
  time: bigint,
}

export interface MultisigScript {
  tag: "Script",
  scriptHash: Buffer,
}

export interface MultisigAllOf {
  tag: "AllOf",
  scripts: Multisig[],
}

export interface MultisigAnyOf {
  tag: "AnyOf",
  scripts: Multisig[],
}

function decodeMultisig(d: Decoder): Multisig {
  let t = decodeTag(d);
  if (t == 121n) {
    decodeBeginIndefiniteArray(d);
    let keyHash = decodeByteArray(d);
    decodeBreak(d);
    return {
      tag: "Signature",
      keyHash,
    };
  } else if (t == 124n) {
    decodeBeginIndefiniteArray(d);
    let required = decodeInteger(d);
    decodeBeginIndefiniteArray(d);
    let scripts = [];
    while (true) {
      let b = d.peek();
      if (b == 0xffn) {
        break;
      }
      let script = decodeMultisig(d);
      scripts.push(script);
    }
    decodeBreak(d);
    decodeBreak(d);
    return {
      tag: "AtLeast",
      required,
      scripts,
    };
  } else if (t == 127n) {
    decodeBeginIndefiniteArray(d);
    let scriptHash = decodeByteArray(d);
    decodeBreak(d);
    return {
      tag: "Script",
      scriptHash,
    };
  } else {
    throw new Error("decodeMultisig: todo");
  }
}

function decodeOptionalMultisig(d: Decoder) {
  let t = decodeTag(d);
  if (t == 121n) {
    decodeBeginIndefiniteArray(d);
    let m = decodeMultisig(d);
    decodeBreak(d);
    return m;
  } else if (t == 122n) {
    let n = decodeBeginArray(d);
    if (n != 0n) {
      throw new Error("decode optional multisig: expected empty array");
    }
    return null;
  } else {
    throw new Error("decode optional multisig: expected optional");
  }
}

export interface PoolDatum {
  identifier: Buffer,
  assetPair: [AssetClass, AssetClass],
  circulatingLp: bigint,
  bidFees: bigint,
  askFees: bigint,
  feeManager: Multisig | null,
  marketOpen: bigint,
  protocolFees: bigint,
}

export function decodePoolDatum(d: Decoder): PoolDatum {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  let identifier = decodeByteArray(d);
  let assetPair = decodeAssetPair(d);
  let circulatingLp = decodeInteger(d);
  let bidFees = decodeInteger(d);
  let askFees = decodeInteger(d);
  let feeManager = decodeOptionalMultisig(d);
  let marketOpen = decodeInteger(d);
  let protocolFees = decodeInteger(d);
  decodeBreak(d);
  //console.log(`circulatingLp: ${stringify(circulatingLp)}`);
  //console.log(`bidFees: ${stringify(bidFees)}`);
  //console.log(`askFees: ${stringify(askFees)}`);
  return {
    identifier,
    assetPair,
    circulatingLp,
    bidFees,
    askFees,
    feeManager,
    marketOpen,
    protocolFees,
  };
}

export function decodeSettingsDatum(d: Decoder): SettingsDatum {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  let settingsAdmin = decodeMultisig(d);
  let metadataAdmin = decodeAddress(d);
  let treasuryAdmin = decodeMultisig(d);
  let treasuryAddress = decodeAddress(d);
  let treasuryAllowance = decodeRational(d);
  let authorizedScoopers = decodeOptional((d) => decodeArray(decodeByteArray, d), d);
  let authorizedStakingKeys = decodeArray(decodeCredential, d);
  let baseFee = decodeInteger(d);
  let simpleFee = decodeInteger(d);
  let strategyFee = decodeInteger(d);
  let poolCreationFee = decodeInteger(d);
  // We don't care about the extensions; we could just skip it but it's actually
  // kind of annoying to implement a "skip the next CBOR item" function to
  // handle the extensions. Fortunately we can just return immediately since
  // this is the last item in the datum
  //let extensions = decodeData(d);
  //decodeBreak(d);
  return {
    settingsAdmin,
    metadataAdmin,
    treasuryAdmin,
    treasuryAddress,
    treasuryAllowance,
    authorizedScoopers,
    authorizedStakingKeys,
    baseFee,
    simpleFee,
    strategyFee,
    poolCreationFee,
    //extensions,
  };
}

function decodeOptional<T>(item: (d: Decoder) => T, d: Decoder): T | null {
  let tag = decodeTag(d);
  if (tag == 121n) {
    decodeBeginIndefiniteArray(d);
    let result = item(d);
    decodeBreak(d);
    return result;
  } else if (tag == 122n) {
    decodeEmptyArray(d);
    return null;
  } else {
    throw "unexpected tag for optional: expected 121 or 122";
  }
}

function decodeArray<T>(item: (d: Decoder) => T, d: Decoder): T[] {
  decodeBeginIndefiniteArray(d);
  let contents = [];
  while (1) {
    let b = d.peek();
    if (b == 0xffn) {
      decodeBreak(d);
      break;
    }
    contents.push(item(d));
  }
  return contents;
}

interface Rational {
  numerator: bigint,
  denominator: bigint,
}

function decodeRational(d: Decoder): Rational {
  decodeBeginIndefiniteArray(d);
  let numerator = decodeInteger(d);
  let denominator = decodeInteger(d);
  decodeBreak(d);
  return {
    numerator,
    denominator,
  };
}

interface Credential {
  tag: bigint,
  cred: Buffer,
}

export function decodeCredential(d: Decoder): Credential {
  let tag = decodeTag(d);
  let cred;
  if (tag == 121n) {
    decodeBeginIndefiniteArray(d);
    cred = decodeByteArray(d);
    decodeBreak(d);
  } else if (tag == 122n) {
    decodeBeginIndefiniteArray(d);
    cred = decodeByteArray(d);
    decodeBreak(d);
  } else {
    throw "unexpected tag for credential: expected 121 or 122";
  }
  return {
    tag,
    cred,
  };
}

export class Address {
  public paymentCred: Buffer
  public paymentTag: bigint
  public constructor(cred: Buffer, tag: bigint) {
    this.paymentCred = cred;
    this.paymentTag = tag;
  }
  public bytes(network: NetworkId): string {
    let isPayment = this.paymentTag == 121n;
    if (network == NetworkId.Mainnet) {
      if (isPayment) {
        return "61" + this.paymentCred.toString("hex");
      } else {
        return "71" + this.paymentCred.toString("hex");
      }
    } else {
      if (isPayment) {
        return "60" + this.paymentCred.toString("hex");
      } else {
        return "70" + this.paymentCred.toString("hex");
      }
    }
  }
}

export function newAddress(cred: Buffer, tag: bigint): Address {
  return new Address(cred, tag);
}

function decodeAddress(d: Decoder): Address {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);

  let paymentTag = decodeTag(d);
  if (paymentTag != 121n && paymentTag != 122n) {
    throw "unexpected tag for payment cred";
  }
  decodeBeginIndefiniteArray(d);
  let paymentCred = decodeByteArray(d);
  decodeBreak(d);

  let stakingTag = decodeTag(d);
  if (stakingTag == 122n) {
    decodeEmptyArray(d);
  } else {
    throw "todo: unimplemented: decodeAddress: staking credential";
  }

  decodeBreak(d);

  return newAddress(paymentCred, paymentTag);
}

type BoundType = NegativeInfinity | Finite | PositiveInfinity

interface NegativeInfinity {
  tag: "NegativeInfinity",
}

interface PositiveInfinity {
  tag: "PositiveInfinity",
}

interface Finite {
  tag: "Finite",
  value: bigint,
}

function decodeBoundType(d: Decoder): BoundType {
  let t = decodeTag(d);
  if (t == 121n) {
    decodeEmptyArray(d);
    return {
      tag: "NegativeInfinity",
    };
  } else if (t == 122n) {
    decodeBeginIndefiniteArray(d);
    let value = decodeInteger(d);
    decodeBreak(d);
    return {
      tag: "Finite",
      value,
    };
  } else if (t == 123n) {
    decodeEmptyArray(d);
    return {
      tag: "PositiveInfinity",
    };
  } else {
    throw new Error("decode bound type: expected tag 121, 122, or 123");
  }
}

function decodeBool(d: Decoder): boolean {
  let t = decodeTag(d);
  if (t == 121n) {
    decodeEmptyArray(d);
    return false;
  } else {
    decodeEmptyArray(d);
    return true;
  }
}

function decodeIntervalBound(d: Decoder) {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  let boundType = decodeBoundType(d);
  let isInclusive = decodeBool(d);
  decodeBreak(d);
  return {
    boundType,
    isInclusive,
  };
}

function decodeValidRange(d: Decoder) {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  let lowerBound = decodeIntervalBound(d);
  let upperBound = decodeIntervalBound(d);
  decodeBreak(d);
  return {
    lowerBound,
    upperBound,
  };
}

export function decodeNewFees(d: Decoder) {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  let validRange = decodeValidRange(d);
  let newBidFees = decodeInteger(d);
  let newAskFees = decodeInteger(d);
  decodeBreak(d);
  return {
    validRange,
    newBidFees,
    newAskFees,
  };
}

export function decodeNewFeeManager(d: Decoder): NewFeeManager {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  let validRange = decodeValidRange(d);
  let feeManager = decodeMultisig(d);
  decodeBreak(d);
  return {
    validRange,
    feeManager,
  };
}

export function withEncoder<X>(f: (e: Encoder, x: X) => void, x: X): Buffer {
  let e = encoder();
  f(e, x);
  return e.complete();
}

export function withEncoderHex<X>(f: (e: Encoder, x: X) => void, x: X): string {
  let e = encoder();
  f(e, x);
  return e.complete().toString('hex');
}

class Encoder {
  public chunks: Buffer[]
  public constructor() {
    this.chunks = [];
  }
  public writeUInt8(n: bigint) {
    this.chunks.push(Buffer.from([Number(n)]));
  }
  public writeBytes(b: Buffer) {
    this.chunks.push(b);
  }
  public complete() {
    return Buffer.concat(this.chunks);
  }
}

export function encoder() {
  return new Encoder();
}

function encodeInteger(e: Encoder, n: bigint) {
  let ty = typeof(n);
  if (ty != "bigint") {
      throw new Error(`encodeInteger: expected bigint, got ${ty}`);
  }
  if (n < 0x18n) {
    e.writeUInt8(n);
  } else if (n <= 0xffn) {
    e.writeUInt8(0x18n);
    e.writeUInt8(n);
  } else if (n <= 0xffffn) {
    e.writeUInt8(0x19n);
    e.writeUInt8(n / BigInt(0x100n));
    e.writeUInt8(n % BigInt(0x100n));
  } else if (n <= 0xffffffffn) {
    e.writeUInt8(0x1an);
    e.writeUInt8(n / BigInt(0x1000000n));
    e.writeUInt8(n / BigInt(0x10000n));
    e.writeUInt8(n / BigInt(0x100n));
    e.writeUInt8(n % BigInt(0x100n));
  } else if (n <= 0xffffffffffffffffn) {
    e.writeUInt8(0x1bn);
    e.writeUInt8(n / 0x100000000000000n);
    e.writeUInt8(n / 0x1000000000000n);
    e.writeUInt8(n / 0x10000000000n);
    e.writeUInt8(n / 0x100000000n);
    e.writeUInt8(n / 0x1000000n);
    e.writeUInt8(n / 0x10000n);
    e.writeUInt8(n / 0x100n);
    e.writeUInt8(n % BigInt(0x100n));
  } else {
    throw new Error("encode integer: todo");
  }
}

function encodeBreak(e: Encoder) {
  e.writeUInt8(0xffn);
}

function encodeBeginArray(e: Encoder, length: bigint) {
  if (length < 0x18n) {
    e.writeUInt8(0x80n + length);
  } else if (length <= 0xffn) {
    e.writeUInt8(0x98n);
    e.writeUInt8(length);
  } else if (length <= 0xffffn) {
    e.writeUInt8(0x99n);
    e.writeUInt8(length / 256n);
    e.writeUInt8(length % 256n);
  } else {
    throw new Error("encode begin array: todo");
  }
}

function encodeBeginArrayIndefinite(e: Encoder) {
  e.writeUInt8(0x9fn);
}

function encodeTag8(e: Encoder, tag: bigint) {
  e.writeUInt8(0xd8n);
  e.writeUInt8(tag);
}

function encodeEmptyArray(e: Encoder) {
  e.writeUInt8(0x80n);
}

type PoolSpendRedeemer = PoolSpendRedeemerPoolScoop | PoolSpendRedeemerPoolManage

interface PoolSpendRedeemerPoolScoop {
  tag: "PoolScoop",
}

interface PoolSpendRedeemerPoolManage {
  tag: "Manage",
}

export function encodePoolSpendRedeemer(e: Encoder, poolSpendRedeemer: PoolSpendRedeemer) {
  // Multivalidator, spend part, so we have to wrap it
  encodeTag8(e, 122n);
  encodeBeginArrayIndefinite(e);
  if (poolSpendRedeemer.tag == "PoolScoop") {
    encodeTag8(e, 121n);
    encodeBeginArrayIndefinite(e);
    throw new Error("encode PoolScoop: todo");
    encodeBreak(e);
  } else if (poolSpendRedeemer.tag == "Manage") {
    encodeTag8(e, 122n);
    encodeEmptyArray(e);
  } else {
    throw new Error("Invalid pool spend redeemer: " + JSON.stringify(poolSpendRedeemer));
  }
  encodeBreak(e);
}

type PoolManageRedeemer = PoolManageRedeemerWithdrawFees | PoolManageRedeemerUpdatePoolFees

interface PoolManageRedeemerWithdrawFees {
  tag: "WithdrawFees",
  amount: bigint,
  treasuryOutput: bigint,
  poolInput: bigint,
}

interface PoolManageRedeemerUpdatePoolFees {
  tag: "UpdatePoolFees",
  poolInputIndex: bigint,
}

export function encodePoolManageRedeemer(e: Encoder, poolManageRedeemer: PoolManageRedeemer) {
  if (poolManageRedeemer.tag == "WithdrawFees") {
    encodeTag8(e, 121n);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, poolManageRedeemer.amount);
    encodeInteger(e, poolManageRedeemer.treasuryOutput);
    encodeInteger(e, poolManageRedeemer.poolInput);
    encodeBreak(e);
  } else if (poolManageRedeemer.tag == "UpdatePoolFees") {
    encodeTag8(e, 122n);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, poolManageRedeemer.poolInputIndex);
    encodeBreak(e);
  } else {
    throw new Error("Invalid pool manage redeemer: " + JSON.stringify(poolManageRedeemer));
  }
}

function encodeBoundType(e: Encoder, boundType: BoundType) {
  if (boundType.tag == "NegativeInfinity") {
    encodeTag8(e, 121n);
    encodeEmptyArray(e);
  } else if (boundType.tag == "Finite") {
    encodeTag8(e, 122n);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, boundType.value);
    encodeBreak(e);
  } else if (boundType.tag == "PositiveInfinity") {
    encodeTag8(e, 123n);
    encodeEmptyArray(e);
  } else {
    throw new Error("Invalid IntervalBoundType: " + JSON.stringify(boundType));
  }
}

function encodeBool(e: Encoder, p: boolean) {
  if (p) {
    encodeTag8(e, 122n);
    encodeEmptyArray(e);
  } else {
    encodeTag8(e, 121n);
    encodeEmptyArray(e);
  }
}

interface IntervalBound {
  boundType: BoundType,
  isInclusive: boolean,
}


function encodeIntervalBound(e: Encoder, intervalBound: IntervalBound) {
  encodeTag8(e, 121n);
  encodeBeginArrayIndefinite(e);
  encodeBoundType(e, intervalBound.boundType);
  encodeBool(e, intervalBound.isInclusive);
  encodeBreak(e);
}

interface ValidityRange {
  lowerBound: IntervalBound,
  upperBound: IntervalBound,
}

function encodeValidityRange(e: Encoder, validityRange: ValidityRange) {
  encodeTag8(e, 121n);
  encodeBeginArrayIndefinite(e);
  encodeIntervalBound(e, validityRange.lowerBound);
  encodeIntervalBound(e, validityRange.upperBound);
  encodeBreak(e);
}

function encodeByteArray(e: Encoder, byteArray: Buffer) {
  if (byteArray.length < 0x18n) {
    e.writeUInt8(0x40n + BigInt(byteArray.length));
    e.writeBytes(byteArray);
  } else if (byteArray.length < 0x100n) {
    e.writeUInt8(0x58n);
    e.writeUInt8(BigInt(byteArray.length));
    e.writeBytes(byteArray);
  } else {
    throw new Error(`encodeByteArray: todo (length=${byteArray.length})`);
  }
}

function encodeMultisig(e: Encoder, multisig: Multisig) {
  if (multisig.tag == "Signature") {
    encodeTag8(e, 121n);
    encodeBeginArrayIndefinite(e);
    encodeByteArray(e, multisig.keyHash);
    encodeBreak(e);
  } else if (multisig.tag == "AllOf") {
    encodeTag8(e, 122n);
    encodeBeginArrayIndefinite(e);
    for (let script of multisig.scripts) {
      encodeMultisig(e, script);
    }
    encodeBreak(e);
  } else if (multisig.tag == "AnyOf") {
    encodeTag8(e, 123n);
    encodeBeginArrayIndefinite(e);
    for (let script of multisig.scripts) {
      encodeMultisig(e, script);
    }
    encodeBreak(e);
  } else if (multisig.tag == "AtLeast") {
    encodeTag8(e, 124n);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, multisig.required);
    encodeBeginArrayIndefinite(e);
    for (let script of multisig.scripts) {
      encodeMultisig(e, script);
    }
    encodeBreak(e);
    encodeBreak(e);
  } else if (multisig.tag == "Before") {
    encodeTag8(e, 125n);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, multisig.time);
    encodeBreak(e);
  } else if (multisig.tag == "After") {
    encodeTag8(e, 126n);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, multisig.time);
    encodeBreak(e);
  } else if (multisig.tag == "Script") {
    encodeTag8(e, 127n);
    encodeBeginArrayIndefinite(e);
    encodeByteArray(e, multisig.scriptHash);
    encodeBreak(e);
  } else {
    throw new Error("Invalid multisig: " + JSON.stringify(multisig));
  }
}

export interface NewFees {
  validRange: ValidityRange,
  newBidFees: bigint,
  newAskFees: bigint,
}

export function encodeNewFees(e: Encoder, newFees: NewFees) {
  encodeTag8(e, 121n);
  encodeBeginArrayIndefinite(e);
  encodeValidityRange(e, newFees.validRange);
  encodeInteger(e, newFees.newBidFees);
  encodeInteger(e, newFees.newAskFees);
  encodeBreak(e);
}

export interface NewFeeManager {
  validRange: ValidityRange,
  feeManager: Multisig,
}

export function encodeNewFeeManager(e: Encoder, newFeeManager: NewFeeManager) {
  encodeTag8(e, 121n);
  encodeBeginArrayIndefinite(e);
  encodeValidityRange(e, newFeeManager.validRange);
  if (!newFeeManager.feeManager) {
    encodeTag8(e, 122n);
    encodeEmptyArray(e);
  } else {
    encodeTag8(e, 121n);
    encodeBeginArrayIndefinite(e);
    encodeMultisig(e, newFeeManager.feeManager);
    encodeBreak(e);
  }
  encodeBreak(e);
}

export interface Signature {
  verificationKey: Buffer,
  signature: Buffer,
}

function encodeSignatures(e: Encoder, signatures: Signature[]) {
  encodeBeginArrayIndefinite(e);
  for (let signature of signatures) {
    encodeBeginArray(e, 2n);
    encodeByteArray(e, signature.verificationKey);
    encodeByteArray(e, signature.signature);
  }
  encodeBreak(e);
}

type ConvenienceFeeManagerRedeemer = ConvenienceFeeManagerRedeemerUpdateFee | ConvenienceFeeManagerRedeemerUpdateFeeManager

export interface ConvenienceFeeManagerRedeemerUpdateFee {
  tag: "UpdateFee",
  newFees: NewFees,
  signatures: Signature[],
}

export interface ConvenienceFeeManagerRedeemerUpdateFeeManager {
  tag: "UpdateFeeManager",
  newFeeManager: NewFeeManager,
  signatures: Signature[],
}

export function encodeConvenienceFeeManagerRedeemer(e: Encoder, convenienceFeeManagerRedeemer: ConvenienceFeeManagerRedeemer) {
  if (convenienceFeeManagerRedeemer.tag == "UpdateFee") {
    encodeTag8(e, 121n);
    encodeBeginArrayIndefinite(e);
    encodeNewFees(e, convenienceFeeManagerRedeemer.newFees);
    encodeSignatures(e, convenienceFeeManagerRedeemer.signatures);
    encodeBreak(e);
  } else if (convenienceFeeManagerRedeemer.tag == "UpdateFeeManager") {
    encodeTag8(e, 122n);
    encodeBeginArrayIndefinite(e);
    encodeNewFeeManager(e, convenienceFeeManagerRedeemer.newFeeManager);
    encodeSignatures(e, convenienceFeeManagerRedeemer.signatures);
    encodeBreak(e);
  } else {
    throw new Error("Invalid convenience fee manager redeemer: " + JSON.stringify(convenienceFeeManagerRedeemer));
  }
}

export type AssetClass = [Buffer, Buffer]

export type AssetPair = [AssetClass, AssetClass]

function encodeAssetClass(e: Encoder, assetClass: AssetClass) {
  encodeBeginArrayIndefinite(e);
  encodeByteArray(e, assetClass[0]);
  encodeByteArray(e, assetClass[1]);
  encodeBreak(e);
}

function encodeAssetPair(e: Encoder, assetPair: AssetPair) {
  encodeBeginArrayIndefinite(e);
  encodeAssetClass(e, assetPair[0]);
  encodeAssetClass(e, assetPair[1]);
  encodeBreak(e);
}

export function encodePoolDatum(e: Encoder, poolDatum: any) {
  encodeTag8(e, 121n);
  encodeBeginArrayIndefinite(e);
  encodeByteArray(e, poolDatum.identifier);
  encodeAssetPair(e, poolDatum.assetPair);
  encodeInteger(e, poolDatum.circulatingLp);
  encodeInteger(e, poolDatum.bidFees);
  encodeInteger(e, poolDatum.askFees);
  if (!poolDatum.feeManager) {
    encodeTag8(e, 122n);
    encodeEmptyArray(e);
  } else {
    encodeTag8(e, 121n);
    encodeBeginArrayIndefinite(e);
    encodeMultisig(e, poolDatum.feeManager);
    encodeBreak(e);
  }
  encodeInteger(e, poolDatum.marketOpen);
  encodeInteger(e, poolDatum.protocolFees);
  encodeBreak(e);
}

function encodeAddress(e: Encoder, address: Address) {
  encodeTag8(e, 121n);
  encodeBeginArrayIndefinite(e);

  encodeTag8(e, address.paymentTag);
  encodeBeginArrayIndefinite(e);
  encodeByteArray(e, address.paymentCred);
  encodeBreak(e);

  encodeTag8(e, 122n);
  encodeEmptyArray(e);

  encodeBreak(e);
}

interface Rational {
  numerator: bigint,
  denominator: bigint,
}

function encodeRational(e: Encoder, r: Rational) {
  encodeBeginArrayIndefinite(e);
  encodeInteger(e, r.numerator);
  encodeInteger(e, r.denominator);
  encodeBreak(e);
}

function encodeAuthorizedScoopers(e: Encoder, authorizedScoopers: Buffer[] | null) {
  if (authorizedScoopers) {
    encodeTag8(e, 121n);
    encodeBeginArrayIndefinite(e);
    encodeBeginArrayIndefinite(e);
    for (let bytes of authorizedScoopers) {
      encodeByteArray(e, bytes);
    }
    encodeBreak(e);
    encodeBreak(e);
  } else {
    encodeTag8(e, 122n);
    encodeEmptyArray(e);
  }
}

function encodeAuthorizedStakingKeys(e: Encoder, authorizedStakingKeys: Credential[]) {
  encodeBeginArrayIndefinite(e);
  for (let cred of authorizedStakingKeys) {
    encodeCredential(e, cred);
  }
  encodeBreak(e);
}

export function encodeCredential(e: Encoder, credential: Credential) {
  encodeTag8(e, credential.tag);
  encodeBeginArrayIndefinite(e);
  encodeByteArray(e, credential.cred);
  encodeBreak(e);
}

export interface SettingsDatum {
  settingsAdmin: Multisig,
  metadataAdmin: Address,
  treasuryAdmin: Multisig,
  treasuryAddress: Address,
  treasuryAllowance: Rational,
  authorizedScoopers: Buffer[] | null,
  authorizedStakingKeys: Credential[],
  baseFee: bigint,
  simpleFee: bigint,
  strategyFee: bigint,
  poolCreationFee: bigint,
}

export function encodeSettingsDatum(e: Encoder, settingsDatum: SettingsDatum) {
  encodeTag8(e, 121n);
  encodeBeginArrayIndefinite(e);
  encodeMultisig(e, settingsDatum.settingsAdmin);
  encodeAddress(e, settingsDatum.metadataAdmin);
  encodeMultisig(e, settingsDatum.treasuryAdmin);
  encodeAddress(e, settingsDatum.treasuryAddress);
  encodeRational(e, settingsDatum.treasuryAllowance);
  encodeAuthorizedScoopers(e, settingsDatum.authorizedScoopers);
  encodeAuthorizedStakingKeys(e, settingsDatum.authorizedStakingKeys);
  encodeInteger(e, settingsDatum.baseFee);
  encodeInteger(e, settingsDatum.simpleFee);
  encodeInteger(e, settingsDatum.strategyFee);
  encodeInteger(e, settingsDatum.poolCreationFee);
  encodeTag8(e, 121n);
  encodeEmptyArray(e);
  encodeBreak(e);
}


function testDecodePoolDatum() {
  let epdHex = "d8799f581cba228444515fbefd2c8725338e49589f206c7f18a33e002b157aac3c9f9f4040ff9f581c99b071ce8580d6a3a11b4902145adb8bfd0d2a03935af8cf66403e1546534245525259ffff1a01c9c380181e181ed8799fd87f9f581ce8dc0595c8d3a7e2c0323a11f5519c32d3b3fb7a994519e38b698b5dffff001a002dc6c0ff";
  let epd = decoder(fromHex(epdHex));
  console.log(`decoded example pool datum: ${stringify(decodePoolDatum(epd))}`);
}
