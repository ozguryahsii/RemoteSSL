import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

// English is the product language; Turkish (or others) can be added later by
// dropping a new resource bundle here.
const resources = {
  en: {
    translation: {
      app: { title: 'RemoteSSL' },
      nav: {
        dashboard: 'Dashboard',
        certificates: 'Certificates',
        monitors: 'Monitors',
        targets: 'Managed Targets',
        requests: 'Certificate Requests',
        deployments: 'Deployments',
        approvals: 'Approvals',
        runners: 'Runners',
        credentials: 'Credentials',
        caIntegrations: 'CA Integrations',
        policies: 'Policies',
        audit: 'Audit',
        settings: 'Settings',
      },
      common: {
        comingSoon: 'This screen arrives in a later phase.',
        apiStatus: 'API status',
        healthy: 'Healthy',
        unreachable: 'Unreachable',
      },
    },
  },
}

i18n.use(initReactI18next).init({
  resources,
  lng: 'en',
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
})

export default i18n
