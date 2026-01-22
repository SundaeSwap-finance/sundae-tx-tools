import {
  NetworkId,
} from "@blaze-cardano/core";

import {
  stringify,
} from "./util.js";

export function decoder(bytes) {
  return {
    bytes: bytes,
    ptr: 0,
    peek: function() {
      if (this.bytes.length <= this.ptr) {
        throw new Error("reached end of input");
      }
      let b = BigInt(this.bytes[this.ptr]);
      return b;
    },
    readUInt8: function() {
      if (this.bytes.length <= this.ptr) {
        throw new Error("reached end of input");
      }
      let b = BigInt(this.bytes[this.ptr]);
      this.ptr += 1;
      return b;
    },
    readBytes: function(n) {
      if (this.bytes.length <= this.ptr + Number(n)) {
        throw new Error("reached end of input");
      }
      let slice = this.bytes.subarray(this.ptr, this.ptr + Number(n));
      this.ptr += Number(n);
      return slice;
    },
    state: function() {
      return JSON.stringify({
        bytes: this.bytes.toString('hex'),
        ptr: this.ptr,
      });
    },
  };
}

function decodeTag(d) {
  let tag = d.readUInt8();
  if (tag == 0xd8) {
    let n = d.readUInt8();
    return n;
  } else if (tag == 0xd9) {
    let upper = d.readUInt8();
    let lower = d.readUInt8();
    return upper * BigInt(256) + lower;
  } else if (tag == 0xda) {
    let w = d.readUInt8();
    let x = d.readUInt8();
    let y = d.readUInt8();
    let z = d.readUInt8();
    return w * BigInt(0x1000000) + x * BigInt(0x10000) + y * BigInt(0x100) + z;
  } else if (tag == 0xdb) {
    throw new Error("decodeTag: todo");
  } else {
    throw new Error("decodeTag: not a tag: " + tag);
  }
}

function decodeBeginArray(d) {
  let b = d.readUInt8();
  if (b >= 0x80 && b < 0x98) {
    return b - BigInt(0x80);
  } else if (b == 0x98) {
    let n = d.readUInt8();
    return n;
  } else {
    console.log(d.state());
    throw new Error("decodeBeginArray: todo");
  }
}

function decodeBeginIndefiniteArray(d) {
  let b = d.readUInt8();
  if (b == 0x9f) {
    return;
  } else {
    throw new Error("decodeBeginIndefiniteArray: not an indefinite array: " + b);
  }
}

function decodeEmptyArray(d) {
  let b = d.readUInt8();
  if (b == 0x80) {
    return;
  } else {
    throw new Error("decodeEmptyArray: expected 0x80");
  }
}

function decodeBreak(d) {
  let b = d.readUInt8();
  if (b == 0xff) {
    return;
  } else {
    throw new Error("decodeBreak: not a break: " + b);
  }
}

function decodeByteArray(d) {
  let b = d.readUInt8();
  if (b >= 0x40 && b < 0x58) {
    return d.readBytes(b - BigInt(0x40));
  } else if (b == 0x58) {
    let n = d.readUInt8();
    return d.readBytes(n);
  } else if (b == 0x59) {
    let upper = d.readUInt8();
    let lower = d.readUInt8();
    return d.readBytes(upper * BigInt(256) + lower);
  } else if (b == 0x5a || b == 0x5b) {
    throw new Error("decodeByteArray: todo"); 
  } else {
    console.log(d.state());
    throw new Error("decodeByteArray: not a byte array: " + b);
  }
}

function decodeAssetClass(d) {
  let _ = decodeBeginIndefiniteArray(d);
  let policy = decodeByteArray(d);
  let token = decodeByteArray(d);
  decodeBreak(d);
  return [policy, token];
}

function decodeAssetPair(d) {
  let _ = decodeBeginIndefiniteArray(d);
  let a = decodeAssetClass(d);
  let b = decodeAssetClass(d);
  decodeBreak(d);
  return [a, b];
}

function decodeInteger(d) {
  let sz = d.readUInt8();
  if (sz < 0x18) {
    return sz;
  } else if (sz == 0x18) {
    let n = d.readUInt8();
    return n;
  } else if (sz == 0x19) {
    let a = d.readUInt8();
    let b = d.readUInt8();
    return a * BigInt(256) + b;
  } else if (sz == 0x1a) {
    let w = d.readUInt8();
    let x = d.readUInt8();
    let y = d.readUInt8();
    let z = d.readUInt8();
    return w * BigInt(0x1000000) + x * BigInt(0x10000) + y * BigInt(0x100) + z;
  } else if (sz == 0x1b) {
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

function decodeMultisig(d) {
  let t = decodeTag(d);
  if (t == 121) {
    decodeBeginIndefiniteArray(d);
    let keyHash = decodeByteArray(d);
    decodeBreak(d);
    return {
      tag: "Signature",
      keyHash,
    };
  } else if (t == 124) {
    decodeBeginIndefiniteArray(d);
    let required = decodeInteger(d);
    decodeBeginIndefiniteArray(d);
    let scripts = [];
    while (true) {
      let b = d.peek();
      if (b == 0xff) {
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
  } else if (t == 127) {
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

function decodeOptionalMultisig(d) {
  let t = decodeTag(d);
  if (t == 121) {
    decodeBeginIndefiniteArray(d);
    let m = decodeMultisig(d);
    decodeBreak(d);
    return m;
  } else if (t == 122) {
    let n = decodeBeginArray(d);
    if (n != 0) {
      throw new Error("decode optional multisig: expected empty array");
    }
  } else {
    throw new Error("decode optional multisig: expected optional");
  }
}

export function decodePoolDatum(d) {
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
  console.log(`circulatingLp: ${stringify(circulatingLp)}`);
  console.log(`bidFees: ${stringify(bidFees)}`);
  console.log(`askFees: ${stringify(askFees)}`);
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

export function decodeSettingsDatum(d) {
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

function decodeOptional(item, d) {
  let tag = decodeTag(d);
  if (tag == 121) {
    decodeBeginIndefiniteArray(d);
    let result = item(d);
    decodeBreak(d);
    return {
      some: result,
    };
  } else if (tag == 122) {
    decodeEmptyArray(d);
    return {};
  } else {
    throw "unexpected tag for optional: expected 121 or 122";
  }
}

function decodeArray(item, d) {
  decodeBeginIndefiniteArray(d);
  let contents = [];
  while (1) {
    let b = d.peek();
    if (b == 0xff) {
      decodeBreak(d);
      break;
    }
    contents.push(item(d));
  }
  return contents;
}

function decodeRational(d) {
  decodeBeginIndefiniteArray(d);
  let numerator = decodeInteger(d);
  let denominator = decodeInteger(d);
  decodeBreak(d);
  return {
    numerator,
    denominator,
  };
}

export function decodeCredential(d) {
  let tag = decodeTag(d);
  let cred;
  if (tag == 121) {
    decodeBeginIndefiniteArray(d);
    cred = decodeByteArray(d);
    decodeBreak(d);
  } else if (tag == 122) {
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

function decodeAddress(d) {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  
  let paymentTag = decodeTag(d);
  let isPayment;
  if (paymentTag == 121) {
    isPayment = true;
  } else if (paymentTag == 122) {
    isPayment = false;
  } else {
    throw "unexpected tag for payment cred";
  }
  decodeBeginIndefiniteArray(d);
  let paymentCred = decodeByteArray(d);
  decodeBreak(d);
  
  let stakingTag = decodeTag(d);
  if (stakingTag == 122) {
    decodeEmptyArray(d);
  } else {
    throw "todo: unimplemented: decodeAddress: staking credential";
  }
  
  decodeBreak(d);

  return {
    bech32: function(network) {
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
    },
    paymentCred,
  };
}

function decodeBoundType(d) {
  let t = decodeTag(d);
  if (t == 121) {
    decodeEmptyArray(d);
    return {
      tag: "NegativeInfinity",
    };
  } else if (t == 122) {
    decodeBeginIndefiniteArray(d);
    let value = decodeInteger(d);
    decodeBreak(d);
    return {
      tag: "Finite",
      value,
    };
  } else if (t == 123) {
    decodeEmptyArray(d);
    return {
      tag: "PositiveInfinity",
    };
  } else {
    throw new Error("decode bound type: expected tag 121, 122, or 123");
  }
}

function decodeBool(d) {
  let t = decodeTag(d);
  if (t == 121) {
    decodeEmptyArray(d);
    return false;
  } else {
    decodeEmptyArray(d);
    return true;
  }
}

function decodeIntervalBound(d) {
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

function decodeValidRange(d) {
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

export function decodeNewFees(d) {
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

export function decodeNewFeeManager(d) {
  let _ = decodeTag(d);
  decodeBeginIndefiniteArray(d);
  let validRange = decodeValidRange(d);
  let multisig = decodeMultisig(d);
  decodeBreak(d);
  return {
    validRange,
    multisig,
  };
}

export function withEncoder(f, x) {
  let e = encoder();
  f(e, x);
  return e.complete();
}

export function withEncoderHex(f, x) {
  let e = encoder();
  f(e, x);
  return e.complete().toString('hex');
}

export function encoder() {
  return {
    chunks: [],
    writeUInt8: function(n) {
      this.chunks.push(Buffer.from([Number(n)]));
    },
    writeBytes: function(b) {
      this.chunks.push(b);
    },
    complete: function() {
      return Buffer.concat(this.chunks);
    }
  };
}

function encodeInteger(e, n) {
  let ty = typeof(n);
  if (ty != "bigint") {
      throw new Error(`encodeInteger: expected bigint, got ${ty}`);
  }
  if (n < 0x18) {
    e.writeUInt8(n);
  } else if (n <= 0xff) {
    e.writeUInt8(0x18);
    e.writeUInt8(n);
  } else if (n <= 0xffff) {
    e.writeUInt8(0x19);
    e.writeUInt8(n / BigInt(0x100n));
    e.writeUInt8(n % BigInt(0x100n));
  } else if (n <= 0xffffffff) {
    e.writeUInt8(0x1a);
    e.writeUInt8(n / BigInt(0x1000000n));
    e.writeUInt8(n / BigInt(0x10000n));
    e.writeUInt8(n / BigInt(0x100n));
    e.writeUInt8(n % BigInt(0x100n));
  } else if (n <= 0xffffffffffffffff) {
    e.writeUInt8(0x1b);
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

function encodeBreak(e) {
  e.writeUInt8(0xff);
}

function encodeBeginArray(e, length) {
  if (length < 0x18) {
    e.writeUInt8(0x80 + length);
  } else if (length <= 0xff) {
    e.writeUInt8(0x98);
    e.writeUInt8(length);
  } else if (length <= 0xffff) {
    e.writeUInt8(0x99);
    e.writeUInt8(length / BigInt(256));
    e.writeUInt8(length % BigInt(256));
  } else {
    throw new Error("encode begin array: todo");
  }
}

function encodeBeginArrayIndefinite(e) {
  e.writeUInt8(0x9f);
}

function encodeTag8(e, tag) {
  e.writeUInt8(0xd8);
  e.writeUInt8(tag);
}

function encodeEmptyArray(e) {
  e.writeUInt8(0x80);
}

export function encodePoolSpendRedeemer(e, poolSpendRedeemer) {
  // Multivalidator, spend part, so we have to wrap it
  encodeTag8(e, 122);
  encodeBeginArrayIndefinite(e);
  if (poolSpendRedeemer.tag == "PoolScoop") {
    encodeTag8(e, 121);
    encodeBeginArrayIndefinite(e);
    throw new Error("encode PoolScoop: todo");
    encodeBreak(e);
  } else if (poolSpendRedeemer.tag == "Manage") {
    encodeTag8(e, 122);
    encodeEmptyArray(e);
  } else {
    throw new Error("Invalid pool spend redeemer: " + JSON.stringify(poolSpendRedeemer));
  }
  encodeBreak(e);
}

export function encodePoolManageRedeemer(e, poolManageRedeemer) {
  if (poolManageRedeemer.tag == "WithdrawFees") {
    encodeTag8(e, 121);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, poolManageRedeemer.amount);
    encodeInteger(e, poolManageRedeemer.treasuryOutput);
    encodeInteger(e, poolManageRedeemer.poolInput);
    encodeBreak(e);
  } else if (poolManageRedeemer.tag == "UpdatePoolFees") {
    encodeTag8(e, 122);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, poolManageRedeemer.poolInputIndex);
    encodeBreak(e);
  } else {
    throw new Error("Invalid pool manage redeemer: " + JSON.stringify(poolManageRedeemer));
  }
}

function encodeBoundType(e, boundType) {
  if (boundType.tag == "NegativeInfinity") {
    encodeTag8(e, 121);
    encodeEmptyArray(e);
  } else if (boundType.tag == "Finite") {
    encodeTag8(e, 122);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, boundType.value);
    encodeBreak(e);
  } else if (boundType.tag == "PositiveInfinity") {
    encodeTag8(e, 123);
    encodeEmptyArray(e);
  } else {
    throw new Error("Invalid IntervalBoundType: " + JSON.stringify(boundType));
  }
}

function encodeBool(e, p) {
  if (p) {
    encodeTag8(e, 122);
    encodeEmptyArray(e);
  } else {
    encodeTag8(e, 121);
    encodeEmptyArray(e);
  }
}

function encodeIntervalBound(e, intervalBound) {
  encodeTag8(e, 121);
  encodeBeginArrayIndefinite(e);
  encodeBoundType(e, intervalBound.boundType);
  encodeBool(e, intervalBound.isInclusive);
  encodeBreak(e);
}

function encodeValidityRange(e, validityRange) {
  encodeTag8(e, 121);
  encodeBeginArrayIndefinite(e);
  encodeIntervalBound(e, validityRange.lowerBound);
  encodeIntervalBound(e, validityRange.upperBound);
  encodeBreak(e);
}

function encodeByteArray(e, byteArray) {
  if (byteArray.length < 0x18) {
    e.writeUInt8(0x40 + byteArray.length);
    e.writeBytes(byteArray);
  } else if (byteArray.length < 0x100) {
    e.writeUInt8(0x58);
    e.writeUInt8(byteArray.length);
    e.writeBytes(byteArray);
  } else {
    throw new Error("encodeByteArray: todo");
  }
}

function encodeMultisig(e, multisig) {
  if (multisig.tag == "Signature") {
    encodeTag8(e, 121);
    encodeBeginArrayIndefinite(e);
    encodeByteArray(e, multisig.keyHash);
    encodeBreak(e);
  } else if (multisig.tag == "AllOf") {
    encodeTag8(e, 122);
    encodeBeginArrayIndefinite(e);
    for (let script of multisig.scripts) {
      encodeMultisig(e, script);
    }
    encodeBreak(e);
    encodeBreak(e);
  } else if (multisig.tag == "AnyOf") {
    encodeTag8(e, 123);
    encodeBeginArrayIndefinite(e);
    for (let script of multisig.scripts) {
      encodeMultisig(e, script);
    }
    encodeBreak(e);
    encodeBreak(e);
  } else if (multisig.tag == "AtLeast") {
    encodeTag8(e, 124);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, multisig.required);
    for (let script of multisig.scripts) {
      encodeMultisig(e, script);
    }
    encodeBreak(e);
    encodeBreak(e);
  } else if (multisig.tag == "Before") {
    encodeTag8(e, 125);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, multisig.time);
    encodeBreak(e);
  } else if (multisig.tag == "After") {
    encodeTag8(e, 126);
    encodeBeginArrayIndefinite(e);
    encodeInteger(e, multisig.time);
    encodeBreak(e);
  } else if (multisig.tag == "Script") {
    encodeTag8(e, 127);
    encodeBeginArrayIndefinite(e);
    encodeByteArray(e, multisig.scriptHash);
    encodeBreak(e);
  } else {
    throw new Error("Invalid multisig: " + JSON.stringify(multisig));
  }
}

export function encodeNewFees(e, newFees) {
  encodeTag8(e, 121);
  encodeBeginArrayIndefinite(e);
  encodeValidityRange(e, newFees.validRange);
  encodeInteger(e, newFees.newBidFees);
  encodeInteger(e, newFees.newAskFees);
  encodeBreak(e);
}

export function encodeNewFeeManager(e, newFeeManager) {
  encodeTag8(e, 121);
  encodeBeginArrayIndefinite(e);
  encodeValidityRange(e, newFeeManager.validRange);
  if (!newFeeManager.feeManager) {
    encodeTag8(e, 122);
    encodeEmptyArray(e);
  } else {
    encodeTag8(e, 121);
    encodeBeginArrayIndefinite(e);
    encodeMultisig(e, newFeeManager.feeManager);
    encodeBreak(e);
  }
  encodeBreak(e);
}

function encodeSignatures(e, signatures) {
  encodeBeginArrayIndefinite(e);
  for (let signature of signatures) {
    encodeBeginArray(e, 2);
    encodeByteArray(e, signature.verificationKey);
    encodeByteArray(e, signature.signature);
  }
  encodeBreak(e);
}

export function encodeConvenienceFeeManagerRedeemer(e, convenienceFeeManagerRedeemer) {
  if (convenienceFeeManagerRedeemer.tag == "UpdateFee") {
    encodeTag8(e, 121);
    encodeBeginArrayIndefinite(e);
    encodeNewFees(e, convenienceFeeManagerRedeemer.newFees);
    encodeSignatures(e, convenienceFeeManagerRedeemer.signatures);
    encodeBreak(e);
  } else if (convenienceFeeManagerRedeemer.tag == "UpdateFeeManager") {
    encodeTag8(e, 122);
    encodeBeginArrayIndefinite(e);
    encodeNewFeeManager(e, convenienceFeeManagerRedeemer.newFeeManager);
    encodeSignatures(e, convenienceFeeManagerRedeemer.signatures);
    encodeBreak(e);
  } else {
    throw new Error("Invalid convenience fee manager redeemer: " + JSON.stringify(convenienceFeeManagerRedeemer));
  }
}

function encodeAssetClass(e, assetClass) {
  encodeBeginArrayIndefinite(e);
  encodeByteArray(e, assetClass[0]);
  encodeByteArray(e, assetClass[1]);
  encodeBreak(e);
}

function encodeAssetPair(e, assetPair) {
  encodeBeginArrayIndefinite(e);
  encodeAssetClass(e, assetPair[0]);
  encodeAssetClass(e, assetPair[1]);
  encodeBreak(e);
}

export function encodePoolDatum(e, poolDatum) {
  encodeTag8(e, 121);
  encodeBeginArrayIndefinite(e);
  encodeByteArray(e, poolDatum.identifier);
  encodeAssetPair(e, poolDatum.assetPair);
  encodeInteger(e, poolDatum.circulatingLp);
  encodeInteger(e, poolDatum.bidFees);
  encodeInteger(e, poolDatum.askFees);
  if (!poolDatum.feeManager) {
    encodeTag8(e, 122);
    encodeEmptyArray(e);
  } else {
    encodeTag8(e, 121);
    encodeBeginArrayIndefinite(e);
    encodeMultisig(e, poolDatum.feeManager);
    encodeBreak(e);
  }
  encodeInteger(e, poolDatum.marketOpen);
  encodeInteger(e, poolDatum.protocolFees);
  encodeBreak(e);
}

function testDecodePoolDatum() {
  let epdHex = "d8799f581cba228444515fbefd2c8725338e49589f206c7f18a33e002b157aac3c9f9f4040ff9f581c99b071ce8580d6a3a11b4902145adb8bfd0d2a03935af8cf66403e1546534245525259ffff1a01c9c380181e181ed8799fd87f9f581ce8dc0595c8d3a7e2c0323a11f5519c32d3b3fb7a994519e38b698b5dffff001a002dc6c0ff";
  let epd = decoder(fromHex(epdHex));
  console.log(`decoded example pool datum: ${stringify(decodePoolDatum(epd))}`);
}
