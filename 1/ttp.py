def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))

ctxt1 = bytes.fromhex('9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0')
ctxt2 = bytes.fromhex('b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83e4')
b = b'flag{'
key = b''
for i in range(0, len(ctxt1), 5):
  key = xor(ctxt2, b)
  b += xor(ctxt1, key)[i:]
  print(b)