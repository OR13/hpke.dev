"use client";

import AppBar from "../components/AppBar";

import { useEffect, useState } from "react";

import { Decrypt } from "../components/Decrypt";
import { isHpkeJweFragment } from "@/services/hpke-url";

export default function DecryptPage() {
  const [hpkeJweFragment, setHpkeJweFragment] = useState<string>();
  const [encodedCompressedCoseEncrypt0, setEncodedCompressedCoseEncrypt0] = useState();
  useEffect(() => {
    if (isHpkeJweFragment(window.location.hash)) {
      setHpkeJweFragment(window.location.hash)
    }

    if (window.location.hash.startsWith("#cose-encrypt0:")) {
      const encoded = window.location.hash.replace('#cose-encrypt0:', '') as any
      setEncodedCompressedCoseEncrypt0(encoded)
    }
  }, []);
  return (
    <AppBar>
      {(hpkeJweFragment || encodedCompressedCoseEncrypt0)? (
        <>
          <Decrypt hpkeJweFragment={hpkeJweFragment} encodedCompressedCoseEncrypt0={encodedCompressedCoseEncrypt0}/>
        </>
      ) : (
        <>
        Scan QR Code.
        </>
      )}
    </AppBar>
  );
}
