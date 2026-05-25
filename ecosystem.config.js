module.exports = {
  apps: [
    {
      name: "file-share",
      script: "server.js",
      cwd: __dirname,
      env: {
        NODE_ENV: "production",
        PORT: "8443",
        HOST: "127.0.0.1",
      },
      autorestart: true,
      max_memory_restart: "300M",
    },
  ],
};
