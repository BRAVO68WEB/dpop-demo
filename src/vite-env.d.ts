/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_LR_ISSUER: string
  readonly VITE_LR_CLIENT_ID: string
  readonly VITE_LR_REDIRECT_URI: string
  readonly VITE_LR_SCOPES: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
