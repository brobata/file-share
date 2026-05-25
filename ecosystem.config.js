module.exports = {
  apps: [
    {
      name: "file-share",
      script: "server.js",
      cwd: __dirname,
      env: {
        NODE_ENV: "production",
        PORT: "4040",
        HOST: "0.0.0.0",
      },
      autorestart: true,
      max_memory_restart: "300M",
    },
  ],
};
