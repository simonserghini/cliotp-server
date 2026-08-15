// pm2 process definition for cliotp-server.
//   pm2 start ecosystem.config.js
module.exports = {
  apps: [
    {
      name: 'cliotp-server',
      script: 'server.js',
      instances: 1,
      exec_mode: 'fork',
      env: {
        PORT: 8080,
        HOST: '0.0.0.0',
      },
      // Override data dir per-deployment if desired:
      // env: { PORT: 8080, HOST: '0.0.0.0', CLIOTP_DATA_DIR: '/var/lib/cliotp-server' },
    },
  ],
};
