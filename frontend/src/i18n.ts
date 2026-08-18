import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

// English is the product language; Turkish (or others) can be added later by
// dropping a new resource bundle here.
const resources = {
  en: {
    translation: {
      app: { title: 'RemoteSSL' },
      nav: {
        home: 'Overview',
        certificates: 'Certificates',
        servers: 'Servers',
        endpoints: 'Watched endpoints',
        activity: 'Activity',
        setup: 'Setup',
        tab: {
          certificates: { all: 'All certificates', requests: 'Requests & CSRs' },
          activity: { installations: 'Installations', approvals: 'Approvals', audit: 'Audit trail' },
          setup: {
            runners: 'Runners', credentials: 'Credentials', keys: 'Keys',
            authorities: 'Certificate authorities', policies: 'Policies', general: 'General',
          },
        },
        // Screen headings still use these; kept so a page title never falls back to a raw key.
        dashboard: 'Overview',
        monitors: 'Watched endpoints',
        targets: 'Servers',
        requests: 'Requests & CSRs',
        deployments: 'Installations',
        approvals: 'Approvals',
        runners: 'Runners',
        credentials: 'Credentials',
        keys: 'Keys',
        caIntegrations: 'Certificate authorities',
        policies: 'Policies',
        audit: 'Audit trail',
        settings: 'General',
      },
      common: {
        comingSoon: 'This screen arrives in a later phase.',
        apiStatus: 'API status',
        healthy: 'Healthy',
        unreachable: 'Unreachable',
        delete: 'Delete',
        close: 'Close',
      },
      monitors: {
        hostPlaceholder: 'hostname or IP',
        sniPlaceholder: 'SNI (optional)',
        add: 'Add monitor',
        addFailed: 'Could not add monitor',
        endpoint: 'Endpoint',
        status: 'Probe status',
        certificate: 'Observed certificate',
        expiry: 'Expiry',
        tls: 'TLS',
        lastProbe: 'Last probe',
        probeNow: 'Probe now',
        probing: 'Probing…',
        days: 'days',
        chainInvalid: 'Chain invalid',
        empty: 'No monitors yet. Add a hostname above to start watching its certificate.',
      },
      certificates: {
        name: 'Certificate',
        status: 'Status',
        expiry: 'Expiry',
        issuer: 'Issuer',
        monitors: 'Monitors',
        versions: 'Versions',
        serial: 'Serial',
        validity: 'Validity',
        key: 'Key',
        lastSeen: 'last seen',
        empty: 'Inventory is empty. Certificates appear automatically as monitors observe them.',
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
