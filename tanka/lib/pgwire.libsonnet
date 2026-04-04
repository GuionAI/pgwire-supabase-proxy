local k = import 'github.com/jsonnet-libs/k8s-libsonnet/1.29/main.libsonnet';

{
  new(params):: {
    local name = 'pgwire-supabase-proxy',
    local registry = 'registry-docker-registry.devops.svc:5000',
    local image = registry + '/pgwire-supabase-proxy:' + params.imageTag,
    local port = 5432,

    local labels = {
      'app.kubernetes.io/name': name,
      'app.kubernetes.io/managed-by': 'tanka',
      'app.kubernetes.io/environment': params.env,
    },

    // DATABASE_URL constructed from CNPG authenticator credentials
    // Host: flicknote-rw (CNPG pooler in infra-dev), db: supabase
    local dbEnv = [
      k.core.v1.envVar.new('DB_USER', '')
      + k.core.v1.envVar.valueFrom.secretKeyRef.withName(params.dbSecret)
      + k.core.v1.envVar.valueFrom.secretKeyRef.withKey('username'),
      k.core.v1.envVar.new('DB_PASSWORD', '')
      + k.core.v1.envVar.valueFrom.secretKeyRef.withName(params.dbSecret)
      + k.core.v1.envVar.valueFrom.secretKeyRef.withKey('password'),
      k.core.v1.envVar.new('DATABASE_URL',
        'postgresql://$(DB_USER):$(DB_PASSWORD)@%s:%d/%s' % [
          params.dbHost, params.dbPort, params.dbName,
        ]),
    ],

    // Config env vars
    local configEnv = [
      // JWT secret from Supabase (HMAC key for token validation)
      k.core.v1.envVar.new('SUPABASE_JWT_SECRET', '')
      + k.core.v1.envVar.valueFrom.secretKeyRef.withName('supabase-jwt-' + params.env)
      + k.core.v1.envVar.valueFrom.secretKeyRef.withKey('secret'),
      k.core.v1.envVar.new('LISTEN_ADDR', '0.0.0.0:5432'),
      k.core.v1.envVar.new('POOL_SIZE', std.toString(params.poolSize)),
    ],

    deployment: k.apps.v1.deployment.new(name, replicas=1, containers=[
      k.core.v1.container.new(name, image)
      + k.core.v1.container.withPorts([
        k.core.v1.containerPort.new(port),
      ])
      + k.core.v1.container.withEnv(dbEnv + configEnv)
      + k.core.v1.container.resources.withRequests(params.resources.requests)
      + k.core.v1.container.resources.withLimits(params.resources.limits)
      + k.core.v1.container.withImagePullPolicy(params.imagePullPolicy)
      + k.core.v1.container.livenessProbe.tcpSocket.withPort(port)
      + k.core.v1.container.livenessProbe.withInitialDelaySeconds(5)
      + k.core.v1.container.livenessProbe.withPeriodSeconds(10)
      + k.core.v1.container.readinessProbe.tcpSocket.withPort(port)
      + k.core.v1.container.readinessProbe.withInitialDelaySeconds(3)
      + k.core.v1.container.readinessProbe.withPeriodSeconds(5)
      + k.core.v1.container.securityContext.withAllowPrivilegeEscalation(false),
    ])
    + k.apps.v1.deployment.metadata.withNamespace(params.namespace)
    + k.apps.v1.deployment.metadata.withLabels(labels)
    + k.apps.v1.deployment.spec.selector.withMatchLabels(labels)
    + k.apps.v1.deployment.spec.template.metadata.withLabels(labels),

    // ClusterIP service so tw CLI (in temenos sidecar) can connect via DNS
    service: k.core.v1.service.new(name, selector=labels, ports=[
      k.core.v1.servicePort.new(port, port),
    ])
    + k.core.v1.service.metadata.withNamespace(params.namespace)
    + k.core.v1.service.metadata.withLabels(labels),
  },
}
