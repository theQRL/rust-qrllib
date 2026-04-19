<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import qrlLogoUrl from './assets/logo.svg'
import {
  loadQrllib,
  type SignatureSnapshot,
  type WalletScheme,
  type WalletSnapshot,
} from './qrllib'

type DemoStep = 'wallet' | 'sign' | 'verify' | 'inspect'

const status = ref('Compiling the wasm package and loading bindings.')
const selectedScheme = ref<WalletScheme>('ml-dsa-87')
const wallet = ref<WalletSnapshot | null>(null)
const message = ref('The sleeper must awaken.')
const signature = ref('')
const verifyResult = ref<boolean | null>(null)
const verifyInput = ref('')
const busy = ref(false)
const xmssHeight = ref(4)
const xmssHashFunction = ref('shake128')
const dark = ref(false)
const activeStep = ref<DemoStep>('wallet')

const steps: Array<{ id: DemoStep; label: string; summary: string }> = [
  {
    id: 'wallet',
    label: 'Wallet',
    summary: 'Choose an algorithm and create browser-side key material.',
  },
  {
    id: 'sign',
    label: 'Sign',
    summary: 'Enter a message and create a detached signature in wasm.',
  },
  {
    id: 'verify',
    label: 'Verify',
    summary: 'Check the signature against the generated public key.',
  },
  {
    id: 'inspect',
    label: 'Inspect',
    summary: 'Review the deterministic material used in the round trip.',
  },
]

const isXmss = computed(() => selectedScheme.value === 'legacy-xmss')
const isSphincs = computed(() => selectedScheme.value === 'sphincsplus-256s')
const activeStepIndex = computed(() => steps.findIndex((step) => step.id === activeStep.value))

const descriptorRows = computed(() => {
  if (!wallet.value) return []

  const rows: Array<[string, string]> = [
    ['Descriptor', wallet.value.descriptorHex],
    ['Public key', wallet.value.publicKeyHex],
    ['Extended seed', wallet.value.extendedSeedHex],
    ['Raw seed', wallet.value.rawSeedHex],
  ]

  if (wallet.value.scheme === 'legacy-xmss') {
    rows.unshift(
      ['Hash function', wallet.value.xmssHashFunction ?? 'unknown'],
      ['Tree height', String(wallet.value.xmssHeight ?? 'n/a')],
      ['OTS index', String(wallet.value.xmssIndex ?? 0)],
    )
  }

  return rows
})

const schemeLabel = computed(() => {
  if (isXmss.value) return 'Legacy XMSS'
  if (isSphincs.value) return 'SPHINCS+-256s robust'
  return 'ML-DSA-87'
})

const walletSummaryRows = computed(() => {
  if (!wallet.value) return []

  const rows: Array<[string, string]> = [
    ['Scheme', schemeLabel.value],
    ['Address', wallet.value.address],
    ['Mnemonic words', String(wallet.value.mnemonic.split(' ').length)],
  ]

  if (wallet.value.scheme === 'legacy-xmss') {
    rows.push(
      ['Tree height', String(wallet.value.xmssHeight ?? 'n/a')],
      ['Current OTS index', String(wallet.value.xmssIndex ?? 0)],
    )
  }

  return rows
})

const signatureSummaryRows = computed(() => [
  ['Message bytes', String(new TextEncoder().encode(message.value).length)],
  ['Signature input bytes', verifyInput.value ? String(Math.floor(verifyInput.value.length / 2)) : '0'],
  ['Verification', verifyResult.value === null ? 'not run' : verifyResult.value ? 'valid' : 'invalid'],
])

const verificationPanel = computed(() => {
  if (verifyResult.value === null) {
    return {
      title: 'Verification not run',
      body: signature.value
        ? 'The signature is ready. Run verification to complete the round trip.'
        : 'Create a signature first, then verify it here.',
      classes: 'bg-amber-50 text-amber-800 ring-amber-600/10 dark:bg-amber-900/20 dark:text-amber-300 dark:ring-amber-400/20',
    }
  }

  if (verifyResult.value) {
    return {
      title: 'Verification passed',
      body: 'The message, detached signature, descriptor, and public key matched.',
      classes: 'bg-emerald-50 text-emerald-800 ring-emerald-600/10 dark:bg-emerald-900/30 dark:text-emerald-300 dark:ring-emerald-400/20',
    }
  }

  return {
    title: 'Verification failed',
    body: 'The signature did not verify. Check whether the message or signature input was changed.',
    classes: 'bg-red-50 text-red-800 ring-red-600/10 dark:bg-red-900/30 dark:text-red-300 dark:ring-red-400/20',
  }
})

const signaturePreview = computed(() => {
  if (!signature.value) return 'No signature created yet.'
  if (signature.value.length <= 64) return signature.value
  return `${signature.value.slice(0, 32)}...${signature.value.slice(-32)}`
})

function setStep(step: DemoStep) {
  activeStep.value = step
}

function stepState(step: DemoStep) {
  if (step === 'wallet') return wallet.value ? 'Ready' : 'Required'
  if (step === 'sign') return signature.value ? 'Signed' : wallet.value ? 'Ready' : 'Locked'
  if (step === 'verify') return verifyResult.value === null ? (signature.value ? 'Ready' : 'Locked') : verifyResult.value ? 'Valid' : 'Invalid'
  return wallet.value ? 'Available' : 'Locked'
}

function stateBadgeClass(step: DemoStep) {
  const state = stepState(step)

  if (state === 'Valid' || state === 'Signed' || state === 'Ready' || state === 'Available') {
    return 'bg-emerald-100 text-emerald-700 ring-emerald-600/10 dark:bg-emerald-900/30 dark:text-emerald-400 dark:ring-emerald-400/20'
  }

  if (state === 'Invalid') {
    return 'bg-red-50 text-red-700 ring-red-600/10 dark:bg-red-900/30 dark:text-red-400 dark:ring-red-400/20'
  }

  if (state === 'Required') {
    return 'bg-amber-50 text-amber-700 ring-amber-600/10 dark:bg-amber-900/20 dark:text-amber-400 dark:ring-amber-400/20'
  }

  return 'bg-zinc-100 text-zinc-700 ring-zinc-600/10 dark:bg-zinc-800 dark:text-zinc-400 dark:ring-zinc-400/20'
}

function verificationValueClass(value: string) {
  if (value === 'valid') return 'text-emerald-600 dark:text-emerald-400'
  if (value === 'invalid') return 'text-red-600 dark:text-red-400'
  if (value === 'not run') return 'text-amber-700 dark:text-amber-400'
  return 'text-gray-900 dark:text-white'
}

function applyTheme(isDark: boolean) {
  document.documentElement.classList.toggle('dark', isDark)
}

function toggleDark() {
  dark.value = !dark.value
  localStorage.setItem('theme', dark.value ? 'dark' : 'light')
  applyTheme(dark.value)
}

function schemeButtonClass(scheme: WalletScheme) {
  return selectedScheme.value === scheme
    ? 'bg-gray-900 text-white dark:bg-white dark:text-gray-900'
    : 'text-gray-700 ring-1 ring-gray-950/10 hover:bg-gray-50 dark:text-gray-300 dark:ring-white/10 dark:hover:bg-white/5'
}

function stepButtonClass(step: DemoStep) {
  return activeStep.value === step
    ? 'bg-gray-100 text-gray-900 dark:bg-white/10 dark:text-white'
    : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-white/5 dark:hover:text-white'
}

async function generateWallet(advance = true) {
  busy.value = true
  status.value = isXmss.value
    ? 'Generating a legacy XMSS wallet and building its Merkle tree inside wasm.'
    : isSphincs.value
      ? 'Generating a SPHINCS+-256s wallet inside wasm from fresh entropy.'
      : 'Generating a deterministic browser wallet from fresh entropy.'

  try {
    const qrllib = await loadQrllib()
    wallet.value = isXmss.value
      ? qrllib.generate_xmss_wallet(xmssHeight.value, xmssHashFunction.value)
      : isSphincs.value
        ? qrllib.generate_sphincsplus_wallet()
        : qrllib.generate_wallet()
    signature.value = ''
    verifyResult.value = null
    verifyInput.value = ''
    if (advance) activeStep.value = 'sign'
    status.value = isXmss.value
      ? 'XMSS wallet ready. Signatures will consume OTS indices one by one.'
      : isSphincs.value
        ? 'SPHINCS wallet ready. Sign a message or restore it from the same extended seed.'
        : 'Wallet ready. Sign a message or rehydrate the same wallet from its extended seed.'
  } catch (error) {
    status.value = String(error)
  } finally {
    busy.value = false
  }
}

async function selectScheme(scheme: WalletScheme) {
  if (selectedScheme.value === scheme) return
  selectedScheme.value = scheme
  activeStep.value = 'wallet'
  await generateWallet(false)
}

async function restoreWallet() {
  if (!wallet.value?.extendedSeedHex) return

  busy.value = true
  status.value = wallet.value.scheme === 'legacy-xmss'
    ? 'Restoring XMSS key material and reapplying the current OTS index.'
    : wallet.value.scheme === 'sphincsplus-256s'
      ? 'Restoring the SPHINCS wallet from its extended seed.'
      : 'Restoring the wallet from its extended seed.'

  try {
    const qrllib = await loadQrllib()
    wallet.value = wallet.value.scheme === 'legacy-xmss'
      ? qrllib.xmss_wallet_from_extended_seed_hex(
          wallet.value.extendedSeedHex,
          wallet.value.xmssIndex ?? 0,
        )
      : wallet.value.scheme === 'sphincsplus-256s'
        ? qrllib.sphincsplus_wallet_from_extended_seed_hex(wallet.value.extendedSeedHex)
        : qrllib.wallet_from_extended_seed_hex(wallet.value.extendedSeedHex)
    signature.value = ''
    verifyResult.value = null
    verifyInput.value = ''
    activeStep.value = 'sign'
    status.value = wallet.value.scheme === 'legacy-xmss'
      ? 'XMSS wallet restored with the same key material and OTS position.'
      : wallet.value.scheme === 'sphincsplus-256s'
        ? 'SPHINCS wallet restored from the same seed material.'
        : 'Wallet restored from the same seed material.'
  } catch (error) {
    status.value = String(error)
  } finally {
    busy.value = false
  }
}

async function signMessage() {
  if (!wallet.value) return

  busy.value = true
  status.value = wallet.value.scheme === 'legacy-xmss'
    ? `Signing the current message at XMSS OTS index ${wallet.value.xmssIndex ?? 0}.`
    : wallet.value.scheme === 'sphincsplus-256s'
      ? 'Signing the current message inside wasm using SPHINCS+-256s.'
      : 'Signing the current message inside wasm using ML-DSA-87.'

  try {
    const qrllib = await loadQrllib()
    const signed = (
      wallet.value.scheme === 'legacy-xmss'
        ? qrllib.sign_xmss_message(
            wallet.value.extendedSeedHex,
            wallet.value.xmssIndex ?? 0,
            message.value,
          )
        : wallet.value.scheme === 'sphincsplus-256s'
          ? qrllib.sign_sphincsplus_message(wallet.value.extendedSeedHex, message.value)
          : qrllib.sign_message(wallet.value.extendedSeedHex, message.value)
    ) as SignatureSnapshot

    signature.value = signed.signatureHex
    verifyInput.value = signed.signatureHex
    verifyResult.value = null

    if (wallet.value.scheme === 'legacy-xmss') {
      wallet.value = {
        ...wallet.value,
        xmssIndex: signed.xmssNextIndex ?? wallet.value.xmssIndex,
      }
      status.value = signed.verified
        ? `Signature created. XMSS advanced to OTS index ${wallet.value.xmssIndex}; verify it in the next step.`
        : 'A signature was produced, but verification failed.'
    } else if (wallet.value.scheme === 'sphincsplus-256s') {
      status.value = signed.verified
        ? 'SPHINCS signature created. The verify step is pre-filled with the detached signature.'
        : 'A signature was produced, but verification failed.'
    } else {
      status.value = signed.verified
        ? 'Signature created. The verify step is pre-filled with the detached signature.'
        : 'A signature was produced, but verification failed.'
    }
    activeStep.value = 'verify'
  } catch (error) {
    status.value = String(error)
  } finally {
    busy.value = false
  }
}

async function verifyMessage() {
  if (!wallet.value || !verifyInput.value) return

  busy.value = true
  status.value = wallet.value.scheme === 'legacy-xmss'
    ? 'Verifying the XMSS signature against the extended public key.'
    : wallet.value.scheme === 'sphincsplus-256s'
      ? 'Verifying the SPHINCS+ detached signature against the current public key.'
      : 'Verifying the detached signature against the current public key.'

  try {
    const qrllib = await loadQrllib()
    verifyResult.value = wallet.value.scheme === 'legacy-xmss'
      ? qrllib.verify_xmss_message(wallet.value.publicKeyHex, message.value, verifyInput.value)
      : wallet.value.scheme === 'sphincsplus-256s'
        ? qrllib.verify_sphincsplus_message(
            wallet.value.publicKeyHex,
            wallet.value.descriptorHex,
            message.value,
            verifyInput.value,
          )
      : qrllib.verify_message(
          wallet.value.publicKeyHex,
          wallet.value.descriptorHex,
          message.value,
          verifyInput.value,
        )
    status.value = verifyResult.value
      ? 'Verification passed with the current wallet material.'
      : 'Verification failed. Check the message, signature, or key material.'
    if (verifyResult.value) activeStep.value = 'inspect'
  } catch (error) {
    status.value = String(error)
  } finally {
    busy.value = false
  }
}

onMounted(async () => {
  const stored = localStorage.getItem('theme')
  dark.value = stored ? stored === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches
  applyTheme(dark.value)
  await generateWallet(false)
})
</script>

<template>
  <div class="antialiased isolate flex min-h-dvh w-full flex-col bg-gray-50 text-gray-900 dark:bg-gray-800 dark:text-white">
    <header class="border-b border-gray-950/5 bg-white dark:border-white/10 dark:bg-gray-900">
      <div class="flex h-14 items-center gap-4 px-4 sm:gap-6 sm:px-6">
        <div class="flex shrink-0 items-center gap-2 text-sm font-semibold text-gray-900 dark:text-white">
          <img :src="qrlLogoUrl" class="size-8" alt="QRL logo" />
          <span class="max-sm:hidden">rust-qrllib wasm</span>
        </div>
        <nav class="flex items-center gap-3 overflow-x-auto text-sm sm:gap-4">
          <a href="https://github.com/theqrl/rust-qrllib" class="shrink-0 text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white">
            GitHub
          </a>
          <a href="https://theqrl.org" class="shrink-0 text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white">
            theqrl.org
          </a>
        </nav>
        <div class="ml-auto hidden text-sm text-gray-400 dark:text-gray-500 sm:block">WebAssembly demo</div>
        <button
          type="button"
          class="shrink-0 rounded-md p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-600 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 dark:text-gray-500 dark:hover:bg-white/10 dark:hover:text-gray-300"
          aria-label="Toggle dark mode"
          @click="toggleDark"
        >
          <svg v-if="dark" class="size-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 2a1 1 0 0 1 1 1v1a1 1 0 1 1-2 0V3a1 1 0 0 1 1-1ZM5.05 5.05a1 1 0 0 1 0 1.414l-.707.707a1 1 0 0 1-1.414-1.414l.707-.707a1 1 0 0 1 1.414 0ZM15.657 4.343a1 1 0 0 1 1.414 0l.707.707a1 1 0 0 1-1.414 1.414l-.707-.707a1 1 0 0 1 0-1.414ZM10 7a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm-6 3a1 1 0 0 1-1 1H2a1 1 0 1 1 0-2h1a1 1 0 0 1 1 1Zm13-1a1 1 0 1 0 0 2h1a1 1 0 1 0 0-2h-1ZM5.05 14.95a1 1 0 0 1 0-1.414l.707-.707a1 1 0 0 1 1.414 1.414l-.707.707a1 1 0 0 1-1.414 0ZM14.243 13.536a1 1 0 0 1 1.414 0l.707.707a1 1 0 0 1-1.414 1.414l-.707-.707a1 1 0 0 1 0-1.414ZM10 15a1 1 0 0 1 1 1v1a1 1 0 1 1-2 0v-1a1 1 0 0 1 1-1Z" clip-rule="evenodd" />
          </svg>
          <svg v-else class="size-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M7.455 2.004a.75.75 0 0 1 .26.77 7 7 0 0 0 9.958 7.967.75.75 0 0 1 1.067.853A8.5 8.5 0 1 1 6.647 1.921a.75.75 0 0 1 .808.083Z" clip-rule="evenodd" />
          </svg>
        </button>
      </div>
    </header>

    <main class="flex flex-1 flex-col gap-6 p-4 md:p-6 lg:p-10">
      <div class="mx-auto w-full max-w-6xl">
        <div>
          <p class="font-mono text-sm uppercase tracking-wide text-amber-600 dark:text-amber-400">
            wasm round trip
          </p>
          <h1 class="mt-2 max-w-[20ch] text-3xl font-semibold tracking-tight text-balance text-gray-900 dark:text-white sm:text-4xl">
            WebAssembly QRL v2.0 signature flow
          </h1>
          <p class="mt-3 max-w-[72ch] text-base text-pretty text-gray-500 dark:text-gray-400">
            Pick a signer, create a detached signature, verify it, then inspect the exact wallet material used by the wasm bindings.
          </p>
        </div>

        <section class="mt-6 overflow-hidden rounded-lg bg-white ring-1 ring-black/5 dark:bg-gray-900 dark:ring-white/10">
          <div class="border-b border-gray-950/5 dark:border-white/10">
            <div class="flex gap-2 overflow-x-auto p-2" role="tablist" aria-label="Round-trip steps">
              <button
                v-for="(step, index) in steps"
                :id="`tab-${step.id}`"
                :key="step.id"
                type="button"
                role="tab"
                :aria-selected="activeStep === step.id"
                :aria-controls="`panel-${step.id}`"
                class="min-w-48 rounded-md p-3 text-left focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500"
                :class="stepButtonClass(step.id)"
                @click="setStep(step.id)"
              >
                <div class="flex items-center justify-between gap-3">
                  <p class="text-sm font-medium">{{ index + 1 }}. {{ step.label }}</p>
                  <div
                    class="rounded-full px-2 py-0.5 text-sm ring-1"
                    :class="stateBadgeClass(step.id)"
                  >
                    {{ stepState(step.id) }}
                  </div>
                </div>
                <p class="mt-1 text-sm text-pretty opacity-75">
                  {{ step.summary }}
                </p>
              </button>
            </div>
          </div>

          <div class="grid gap-px bg-gray-950/5 dark:bg-white/10 lg:grid-cols-[13fr_7fr]">
            <div class="bg-white p-5 dark:bg-gray-900 sm:p-6">
              <div
                v-if="activeStep === 'wallet'"
                id="panel-wallet"
                role="tabpanel"
                aria-labelledby="tab-wallet"
                class="grid gap-6"
              >
                <div>
                  <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Step 1</p>
                  <h2 class="mt-1 text-2xl font-semibold tracking-tight text-balance text-gray-900 dark:text-white">
                    Choose the signer and generate wallet material.
                  </h2>
                  <p class="mt-2 text-base text-pretty text-gray-500 dark:text-gray-400">
                    The demo creates keys in the browser through the compiled wasm package. Changing the scheme regenerates the wallet and clears the signature.
                  </p>
                </div>

                <div class="flex flex-wrap gap-2">
                  <button
                    type="button"
                    class="rounded-md px-3 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
                    :class="schemeButtonClass('ml-dsa-87')"
                    :disabled="busy"
                    @click="selectScheme('ml-dsa-87')"
                  >
                    ML-DSA-87
                  </button>
                  <button
                    type="button"
                    class="rounded-md px-3 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
                    :class="schemeButtonClass('sphincsplus-256s')"
                    :disabled="busy"
                    @click="selectScheme('sphincsplus-256s')"
                  >
                    SPHINCS+-256s
                  </button>
                  <button
                    type="button"
                    class="rounded-md px-3 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
                    :class="schemeButtonClass('legacy-xmss')"
                    :disabled="busy"
                    @click="selectScheme('legacy-xmss')"
                  >
                    Legacy XMSS
                  </button>
                </div>

                <div
                  v-if="isXmss"
                  class="grid gap-4 rounded-md bg-gray-50 p-4 ring-1 ring-gray-950/5 dark:bg-white/5 dark:ring-white/10 sm:grid-cols-2"
                >
                  <div>
                    <label class="text-sm font-medium text-gray-900 dark:text-white" for="xmss-height">XMSS height</label>
                    <select
                      id="xmss-height"
                      v-model.number="xmssHeight"
                      name="xmss-height"
                      class="mt-1.5 w-full rounded-md bg-white px-3 py-2 text-base text-gray-900 ring-1 ring-black/10 focus:outline-none focus:ring-2 focus:ring-amber-500 dark:bg-gray-900 dark:text-white dark:ring-white/10 sm:text-sm"
                    >
                      <option :value="4">4</option>
                      <option :value="6">6</option>
                      <option :value="8">8</option>
                      <option :value="10">10</option>
                    </select>
                  </div>

                  <div>
                    <label class="text-sm font-medium text-gray-900 dark:text-white" for="xmss-hash">Hash function</label>
                    <select
                      id="xmss-hash"
                      v-model="xmssHashFunction"
                      name="xmss-hash"
                      class="mt-1.5 w-full rounded-md bg-white px-3 py-2 text-base text-gray-900 ring-1 ring-black/10 focus:outline-none focus:ring-2 focus:ring-amber-500 dark:bg-gray-900 dark:text-white dark:ring-white/10 sm:text-sm"
                    >
                      <option value="shake128">SHAKE128</option>
                      <option value="shake256">SHAKE256</option>
                      <option value="sha2_256">SHA2-256</option>
                    </select>
                  </div>
                </div>

                <div class="flex flex-wrap gap-3">
                  <button
                    type="button"
                    class="rounded-md bg-amber-500 px-3 py-2 text-sm font-semibold text-white hover:bg-amber-600 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="busy"
                    @click="generateWallet()"
                  >
                    Generate and continue
                  </button>
                  <button
                    type="button"
                    class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 ring-1 ring-gray-950/10 hover:bg-gray-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 disabled:cursor-not-allowed disabled:opacity-50 dark:text-gray-300 dark:ring-white/10 dark:hover:bg-white/5"
                    :disabled="busy || !wallet"
                    @click="restoreWallet"
                  >
                    Rehydrate current wallet
                  </button>
                </div>
              </div>

              <div
                v-else-if="activeStep === 'sign'"
                id="panel-sign"
                role="tabpanel"
                aria-labelledby="tab-sign"
                class="grid gap-6"
              >
                <div>
                  <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Step 2</p>
                  <h2 class="mt-1 text-2xl font-semibold tracking-tight text-balance text-gray-900 dark:text-white">
                    Sign one message with the current wallet.
                  </h2>
                  <p class="mt-2 text-base text-pretty text-gray-500 dark:text-gray-400">
                    This produces a detached hex signature and pre-fills the verify step. For XMSS, signing advances the OTS index.
                  </p>
                </div>

                <div>
                  <label class="text-sm font-medium text-gray-900 dark:text-white" for="message">Message</label>
                  <textarea
                    id="message"
                    v-model="message"
                    name="message"
                    rows="6"
                    class="mt-1.5 min-h-48 w-full rounded-md bg-white px-3 py-2 text-base text-gray-900 ring-1 ring-black/10 focus:outline-none focus:ring-2 focus:ring-amber-500 dark:bg-gray-800 dark:text-white dark:ring-white/10 sm:text-sm"
                  />
                </div>

                <div class="flex flex-wrap gap-3">
                  <button
                    type="button"
                    class="rounded-md bg-amber-500 px-3 py-2 text-sm font-semibold text-white hover:bg-amber-600 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="busy || !wallet"
                    @click="signMessage"
                  >
                    Sign and continue
                  </button>
                  <button
                    type="button"
                    class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 ring-1 ring-gray-950/10 hover:bg-gray-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 dark:text-gray-300 dark:ring-white/10 dark:hover:bg-white/5"
                    @click="setStep('wallet')"
                  >
                    Back to wallet
                  </button>
                </div>
              </div>

              <div
                v-else-if="activeStep === 'verify'"
                id="panel-verify"
                role="tabpanel"
                aria-labelledby="tab-verify"
                class="grid gap-6"
              >
                <div>
                  <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Step 3</p>
                  <h2 class="mt-1 text-2xl font-semibold tracking-tight text-balance text-gray-900 dark:text-white">
                    Verify the detached signature.
                  </h2>
                  <p class="mt-2 text-base text-pretty text-gray-500 dark:text-gray-400">
                    The signature field is editable so the failure case is easy to test. A valid result completes the round trip.
                  </p>
                </div>

                <div>
                  <label class="text-sm font-medium text-gray-900 dark:text-white" for="signature">Detached signature</label>
                  <textarea
                    id="signature"
                    v-model="verifyInput"
                    name="signature"
                    rows="8"
                    aria-label="Detached signature hex"
                    class="mt-1.5 min-h-64 w-full rounded-md bg-white px-3 py-2 font-mono text-base text-gray-900 ring-1 ring-black/10 focus:outline-none focus:ring-2 focus:ring-amber-500 dark:bg-gray-800 dark:text-white dark:ring-white/10 sm:text-sm/6"
                  />
                </div>

                <div class="rounded-md p-4 ring-1" :class="verificationPanel.classes">
                  <p class="text-sm font-semibold">{{ verificationPanel.title }}</p>
                  <p class="mt-2 text-sm/6 text-pretty">{{ verificationPanel.body }}</p>
                </div>

                <div class="flex flex-wrap gap-3">
                  <button
                    type="button"
                    class="rounded-md bg-amber-500 px-3 py-2 text-sm font-semibold text-white hover:bg-amber-600 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="busy || !wallet || !verifyInput"
                    @click="verifyMessage"
                  >
                    Verify signature
                  </button>
                  <button
                    type="button"
                    class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 ring-1 ring-gray-950/10 hover:bg-gray-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 dark:text-gray-300 dark:ring-white/10 dark:hover:bg-white/5"
                    @click="setStep('sign')"
                  >
                    Back to sign
                  </button>
                </div>
              </div>

              <div
                v-else
                id="panel-inspect"
                role="tabpanel"
                aria-labelledby="tab-inspect"
                class="grid gap-6"
              >
                <div>
                  <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Step 4</p>
                  <h2 class="mt-1 text-2xl font-semibold tracking-tight text-balance text-gray-900 dark:text-white">
                    Inspect what completed the round trip.
                  </h2>
                  <p class="mt-2 text-base text-pretty text-gray-500 dark:text-gray-400">
                    These are the deterministic wallet values and the final verification status exposed by the wasm API.
                  </p>
                </div>

                <div class="grid gap-3">
                  <article
                    v-for="[label, value] in descriptorRows"
                    :key="label"
                    class="rounded-md bg-gray-50 p-4 ring-1 ring-gray-950/5 dark:bg-white/5 dark:ring-white/10"
                  >
                    <p class="text-sm font-medium text-gray-500 dark:text-gray-400">{{ label }}</p>
                    <p class="mt-2 break-all font-mono text-sm/6 tabular-nums text-gray-900 dark:text-white">{{ value }}</p>
                  </article>
                </div>

                <div class="flex flex-wrap gap-3">
                  <button
                    type="button"
                    class="rounded-md bg-amber-500 px-3 py-2 text-sm font-semibold text-white hover:bg-amber-600 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="busy"
                    @click="generateWallet()"
                  >
                    Start another round trip
                  </button>
                  <button
                    type="button"
                    class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 ring-1 ring-gray-950/10 hover:bg-gray-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500 dark:text-gray-300 dark:ring-white/10 dark:hover:bg-white/5"
                    @click="setStep('verify')"
                  >
                    Back to verify
                  </button>
                </div>
              </div>
            </div>

            <aside class="bg-gray-50 p-5 dark:bg-gray-900 sm:p-6">
              <div class="grid gap-5">
                <div>
                  <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Current step</p>
                  <p class="mt-1 text-2xl font-semibold tracking-tight tabular-nums text-gray-900 dark:text-white">
                    {{ activeStepIndex + 1 }} / {{ steps.length }}
                  </p>
                </div>

                <div class="rounded-md bg-white p-4 ring-1 ring-gray-950/5 dark:bg-white/5 dark:ring-white/10">
                  <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Runtime status</p>
                  <p class="mt-2 text-sm/6 text-pretty text-gray-700 dark:text-gray-300">{{ status }}</p>
                </div>

                <div class="grid gap-3">
                  <article
                    v-for="[label, value] in walletSummaryRows"
                    :key="label"
                    class="rounded-md bg-white p-3 ring-1 ring-gray-950/5 dark:bg-white/5 dark:ring-white/10"
                  >
                    <p class="text-sm font-medium text-gray-500 dark:text-gray-400">{{ label }}</p>
                    <p class="mt-1 break-all font-mono text-sm/6 tabular-nums text-gray-900 dark:text-white">{{ value }}</p>
                  </article>
                </div>

                <div class="rounded-md bg-white p-4 ring-1 ring-gray-950/5 dark:bg-white/5 dark:ring-white/10">
                  <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Signature preview</p>
                  <p class="mt-2 break-all font-mono text-sm/6 text-gray-900 dark:text-white">
                    {{ signaturePreview }}
                  </p>
                </div>

                <dl class="grid gap-px overflow-hidden rounded-md bg-gray-950/5 text-sm dark:bg-white/10">
                  <div
                    v-for="[label, value] in signatureSummaryRows"
                    :key="label"
                    class="grid grid-cols-[2fr_3fr] gap-3 bg-white p-3 dark:bg-gray-900"
                  >
                    <dt class="font-medium text-gray-500 dark:text-gray-400">{{ label }}</dt>
                    <dd class="break-all font-mono tabular-nums" :class="verificationValueClass(value)">{{ value }}</dd>
                  </div>
                </dl>

                <div class="rounded-md p-4 ring-1" :class="verificationPanel.classes">
                  <p class="text-sm font-semibold">{{ verificationPanel.title }}</p>
                  <p class="mt-2 text-sm/6 text-pretty">{{ verificationPanel.body }}</p>
                </div>

                <div
                  v-if="isXmss"
                  class="rounded-md bg-amber-50 p-4 ring-1 ring-amber-600/10 dark:bg-amber-900/20 dark:ring-amber-400/20"
                >
                  <p class="text-sm font-medium text-amber-800 dark:text-amber-300">XMSS state is explicit</p>
                  <p class="mt-2 text-sm/6 text-pretty text-amber-700 dark:text-amber-400">
                    Signing consumes one OTS index. The demo keeps the index visible instead of hiding stateful signing semantics.
                  </p>
                </div>
              </div>
            </aside>
          </div>
        </section>
      </div>
    </main>

    <footer class="border-t border-gray-950/5 bg-white px-4 py-6 dark:border-white/10 dark:bg-gray-900 sm:px-6">
      <div class="mx-auto flex max-w-6xl flex-col items-center gap-3 text-sm text-gray-400 dark:text-gray-500 sm:flex-row sm:justify-between">
        <p>QRL Rust WebAssembly Demo</p>
        <div class="flex items-center gap-4">
          <a href="https://theqrl.org" target="_blank" rel="noopener" class="hover:text-gray-600 dark:hover:text-gray-300">theqrl.org</a>
          <a href="https://github.com/theqrl" target="_blank" rel="noopener" class="hover:text-gray-600 dark:hover:text-gray-300">GitHub</a>
          <a href="https://theqrl.org/discord" target="_blank" rel="noopener" class="hover:text-gray-600 dark:hover:text-gray-300">Discord</a>
        </div>
      </div>
    </footer>
  </div>
</template>
