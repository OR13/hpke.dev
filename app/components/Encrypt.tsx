"use client";


import { Button, Box, ToggleButton, ToggleButtonGroup } from "@mui/material";

import * as React from "react";
import * as jose from "jose";

import Typography from "@mui/material/Typography";
import { useRouter } from "next/navigation";
import { useParams } from "next/navigation";
import { Chip } from "@mui/material";

import LockPerson from "@mui/icons-material/LockPerson";

import { encrypt as hpkeEncrypt, type HpkeMode } from "@hpke-jose";
import { encodeHpkeJweFragment } from "@/services/hpke-url";

import CodeMirror from '@uiw/react-codemirror';
import { markdown } from '@codemirror/lang-markdown';
import { andromeda } from '@uiw/codemirror-theme-andromeda';

import { EditorView } from "@uiw/react-codemirror"


import * as cose from '@transmute/cose'
import pako from 'pako'

export function Encrypt({publicKeyJwk}: {publicKeyJwk: any}) {
  const router = useRouter()
  const [message, setMessage] = React.useState(`
# Markdown Message
> ⌛ My lungs taste the air of Time Blown past falling sands ⌛
  `.trim()+'\n')
  // Both HPKE JWE formats from draft-ietf-jose-hpke-encrypt-22.
  const [hpkeMode, setHpkeMode] = React.useState<HpkeMode>('integrated')
  const encryptTo = async (type: 'jose'| 'cose') => {
    const plaintext = new TextEncoder().encode(message)
    if (type === 'jose'){
      const jwe = await hpkeEncrypt(plaintext, publicKeyJwk, {
        mode: hpkeMode,
        protectedHeader: publicKeyJwk.kid ? { kid: publicKeyJwk.kid } : undefined,
      })
      const hash = '/decrypt#' + encodeHpkeJweFragment(jwe)
      window.location.href = window.location.origin + hash
    } else if (type === 'cose'){
      const ciphertext = await cose.encrypt.direct({
        protectedHeader: cose.ProtectedHeader([
          [cose.Protected.Alg, cose.Direct["HPKE-Base-P256-SHA256-AES128GCM"]],
        ]),
        plaintext,
        recipients: {
          keys: [publicKeyJwk]
        },
      });
      const compressed = pako.deflate(ciphertext)
      const hash = '/decrypt#cose-encrypt0:' + jose.base64url.encode(compressed)
      window.location.href = window.location.origin + hash
    }
  };
  return (
    <>
    <Box sx={{ display: "flex", flexDirection: "row", mb: 2 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h6" component="div">
            Recipient
          </Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center" }}>
          <ToggleButtonGroup
            size="small"
            exclusive
            color="secondary"
            value={hpkeMode}
            onChange={(_e, value) => {
              if (value) setHpkeMode(value as HpkeMode)
            }}
            aria-label="HPKE JWE format"
            sx={{ mr: 2 }}
          >
            <ToggleButton value="integrated" aria-label="Integrated Encryption">
              Integrated
            </ToggleButton>
            <ToggleButton value="keyEncryption" aria-label="Key Encryption">
              Key Encryption
            </ToggleButton>
          </ToggleButtonGroup>
          <Button
            variant="outlined"
            color="secondary"
            onClick={()=>{
              encryptTo('jose')
            }}
            endIcon={<LockPerson />}
          >
            JOSE Encrypt
          </Button>
          <Button
            sx={{ml: 2}}
            variant="contained"
            color="secondary"
            onClick={()=>{
              encryptTo('cose')
            }}
            endIcon={<LockPerson />}
          >
            COSE Encrypt
          </Button>
        </Box>
      </Box>
      <Chip
        deleteIcon={<LockPerson />}
        onDelete={() => {}}
        label={publicKeyJwk.kid}
      />
      <Box sx={{mt: 2}}>
      <CodeMirror 
      theme={andromeda}
      value={message}  
      onChange={(value)=>{
        setMessage(value)
      }}
      extensions={[
        markdown(),
        EditorView.lineWrapping
      ]} 
    />
      </Box>
    </>
      
  );
}
