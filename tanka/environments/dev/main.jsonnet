local pgwire = import '../../lib/pgwire.libsonnet';

local params = {
  env: 'dev',
  namespace: 'supa-dev',
  imageTag: 'latest',
  imagePullPolicy: 'Always',

  // CNPG pooler connection (flicknote-rw is in infra-dev, serves supabase db)
  dbSecret: 'cnpg-authenticator-password-dev',
  dbHost: 'flicknote-rw.infra-dev.svc',
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
