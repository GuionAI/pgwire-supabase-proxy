local pgwire = import '../../lib/pgwire.libsonnet';

local params = {
  env: 'prod',
  namespace: 'supa-prod',
  imageTag: 'latest',
  imagePullPolicy: 'IfNotPresent',

  // CNPG pooler connection (flicknote-rw is in infra-prod, serves supabase db)
  dbSecret: 'cnpg-authenticator-password-prod',
  dbHost: 'flicknote-rw.infra-prod.svc',
  dbPort: 5432,
  dbName: 'supabase',

  // Connection pool size per user
  poolSize: 10,

  resources: {
    requests: { memory: '64Mi', cpu: '50m' },
    limits: { memory: '512Mi', cpu: '1' },
  },
};

{ proxy: pgwire.new(params) }
