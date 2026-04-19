export type WalletScheme = 'ml-dsa-87' | 'sphincsplus-256s' | 'legacy-xmss'

export type WalletSnapshot = {
  scheme: WalletScheme
  address: string
  descriptorHex: string
  extendedSeedHex: string
  mnemonic: string
  publicKeyHex: string
  rawSeedHex: string
  xmssHashFunction?: string | null
  xmssHeight?: number | null
  xmssIndex?: number | null
}

export type SignatureSnapshot = {
  scheme: WalletScheme
  signatureHex: string
  verified: boolean
  xmssIndex?: number | null
  xmssNextIndex?: number | null
}

export type DilithiumSnapshot = {
  scheme: 'legacy-dilithium'
  seedHex: string
  publicKeyHex: string
}

type QrllibBindings = {
  default: (input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module) => Promise<void>
  generate_wallet: () => WalletSnapshot
  wallet_from_extended_seed_hex: (extendedSeedHex: string) => WalletSnapshot
  sign_message: (extendedSeedHex: string, message: string) => SignatureSnapshot
  verify_message: (
    publicKeyHex: string,
    descriptorHex: string,
    message: string,
    signatureHex: string,
  ) => boolean
  generate_dilithium_signer: () => DilithiumSnapshot
  dilithium_from_hex_seed: (seedHex: string) => DilithiumSnapshot
  sign_dilithium_message: (seedHex: string, message: string) => SignatureSnapshot
  verify_dilithium_message: (
    publicKeyHex: string,
    message: string,
    signatureHex: string,
  ) => boolean
  generate_sphincsplus_wallet: () => WalletSnapshot
  sphincsplus_wallet_from_extended_seed_hex: (extendedSeedHex: string) => WalletSnapshot
  sign_sphincsplus_message: (
    extendedSeedHex: string,
    message: string,
  ) => SignatureSnapshot
  verify_sphincsplus_message: (
    publicKeyHex: string,
    descriptorHex: string,
    message: string,
    signatureHex: string,
  ) => boolean
  generate_xmss_wallet: (height: number, hashFunction: string) => WalletSnapshot
  xmss_wallet_from_extended_seed_hex: (extendedSeedHex: string, index: number) => WalletSnapshot
  sign_xmss_message: (
    extendedSeedHex: string,
    index: number,
    message: string,
  ) => SignatureSnapshot
  verify_xmss_message: (publicKeyHex: string, message: string, signatureHex: string) => boolean
}

let wasm: Promise<QrllibBindings> | null = null

export async function loadQrllib() {
  if (!wasm) {
    wasm = import('../../crates/qrllib-wasm/pkg/qrllib_wasm').then(async (mod) => {
      const bindings = mod as unknown as QrllibBindings
      await bindings.default()
      return bindings
    })
  }

  return wasm
}
