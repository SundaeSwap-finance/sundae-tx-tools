export function fromHex(hexBytes: string) {
  if (hexBytes.length % 2 != 0) {
    throw new Error("fromHex: odd length: " + hexBytes);
  }
  return Buffer.from(hexBytes, 'hex');
}

export function stringify(o: any) {
  return JSON.stringify(o, (_, v) => typeof v === 'bigint' ? v.toString() : v);
}
