To run:

```
$ npx tsc
$ export SKEY_HEX=...
$ export BLOCKFROST_PROJECT_ID=...
# export MAINNET=1
$ node index.js ...
```

To update fee manager:

```
$ node index.js \
  --buildUpdateFeeManager \
  --address addr_test1vqp4mmnx647vyutfwugav0yvxhl6pdkyg69x4xqzfl4vwwck92a9t \
  --references references \
  --poolIdent ba228444515fbefd2c8725338e49589f206c7f18a33e002b157aac3c \
  --poolAddress addr_test1xpz2r6ednav2m48tryet6qzgu6segl59u0ly7v54dggsg9xvy7vq4p2hl6wm9jdvpgn80ax3xpkm7yrgnxphtrct3klq005j2r \
  --blueprint preview.blueprint.json \
  --feeManagerAddress stake_test17r5dcpv4erf60ckqxgapra23nsed8vlm02v52x0r3d5ckhgaxusdx \
  --feeManagerRedeemer d87a9fd8799fd8799fd8799fd87980d87a80ffd8799fd87b80d87a80ffffd8799fd87f9f581ce8dc0595c8d3a7e2c0323a11f5519c32d3b3fb7a994519e38b698b5dffffff9f8258206f2b757b39b783977e0306bd2751fa3db19f2f8d52d478f44a4a03efb0fa2b2958404fe1e459953eaf74bd2c713272e9e9c3b41a0ddd5b4ab5b4d3730dd216bc0038e63f10c6f703e702a80511c46170fe3d0b997ad75dcc25dabb822a960f31fd0bffff
  --updateFeeManager \
  --feeManager '{ "type": "Script", "scriptHash": "e8dc0595c8d3a7e2c0323a11f5519c32d3b3fb7a994519e38b698b5d" }'
```

To update fees:

```
node index.js \
  --buildUpdateFeeManager \
  --address addr_test1vqp4mmnx647vyutfwugav0yvxhl6pdkyg69x4xqzfl4vwwck92a9t \
  --references references \
  --poolIdent ba228444515fbefd2c8725338e49589f206c7f18a33e002b157aac3c \
  --poolAddress
  addr_test1xpz2r6ednav2m48tryet6qzgu6segl59u0ly7v54dggsg9xvy7vq4p2hl6wm9jdvpgn80ax3xpkm7yrgnxphtrct3klq005j2r \
  --blueprint preview.blueprint.json \
  --feeManagerRedeemer d8799fd8799fd8799fd8799fd87980d87a80ffd8799fd87b80d87a80ffff18641864ff9f8258206f2b757b39b783977e0306bd2751fa3db19f2f8d52d478f44a4a03efb0fa2b295840be71d864bc2c8a5435e6ec1c56c199f90e003724df981f62b71c8123e3f06f11f012f67ca2df0a08995f6383ca5b2d991908912a12f993c7c81ef19ecf4c690bffff \
  --feeManagerAddress stake_test17r5dcpv4erf60ckqxgapra23nsed8vlm02v52x0r3d5ckhgaxusdx \
  --feeManagerScript feeManagerScript \
  --updateFees \
  --askFee 100 \
  --bidFee 100
```

To construct an update-fees object:

```
node index.js --prepareUpdate --updateFees --newBidFees 100 --newAskFees 100
```

To sign a message with the configured key:

```
node index.js --signMessage --message d8799fd8799fd8799fd87980d87a80ffd8799fd87b80d87a80ffff18641864ff
```

To construct a redeemer from an update object and signatures ('signatures'
object must be an array of (pubkey, signature) tuples):

```
node index.js --makeRedeemer --updateFees --updateObject d8799fd8799fd8799fd87980d87a80ffd8799fd87b80d87a80ffff18641864ff --signatures '[["6f2b757b39b783977e0306bd2751fa3db19f2f8d52d478f44a4a03efb0fa2b29","be71d864bc2c8a5435e6ec1c56c199f90e003724df981f62b71c8123e3f06f11f012f67ca2df0a08995f6383ca5b2d991908912a12f993c7c81ef19ecf4c690b"]]'
```

To perform an update of a pool using the fee manager stake validator, perform
these steps:
1. Use --prepareUpdate to create an object describing the desired update.
2. Obtain ed25519 signatures for the object from all required parties (manager
   in case of UpdateFee, owner in case of UpdateFeeManager).
3. Use --makeRedeemer to combine the signatures and the update object. The
   script will verify that all signatures are correct.

To withdraw protocol fees:

```
node index.js \
  --autoWithdrawRewards \
  --poolAddress addr1x8srqftqemf0mjlukfszd97ljuxdp44r372txfcr75wrz26rnxqnmtv3hdu2t6chcfhl2zzjh36a87nmd6dwsu3jenqsslnz7e \
  --needed 10000000 \
  --walletAddress addr1v92m7sgckq0pc72xgldexa0lepe7gdwhxuq8k2kmcjxdh2skxa0m4 \
  --settingsAddress addr1w9ke67k2ckdyg60v22ajqugxze79e0ax3yqgl7nway4vc5q84hpqs \
  --settingsScriptHash 6d9d7acac59a4469ec52bb207106167c5cbfa689008ffa6ee92acc50 \
  --references references-mainnet \
  --signers 55bf4118b01e1c794647db9375ffc873e435d737007b2adbc48cdbaa \
  --withheldAddress addr1v92m7sgckq0pc72xgldexa0lepe7gdwhxuq8k2kmcjxdh2skxa0m4 \
  --blueprint mainnet.blueprint.json \
  --treasuryAddress addr1w8qd02ncr520yph37erg7z3dfyv8684uhr6eckwht5xz0fc6vn2tg
```
