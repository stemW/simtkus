module.exports = {
  apps: [
    {
      name: 'simtk',
      script: 'server.js',
      cwd: '/home/youruser/SimTk/github_public', // change to the deployed path on your server
      watch: false,
      env: {
        NODE_ENV: 'production',
        PORT: 8080,
        HOSTNAME: 'simtkus.com'
        // other env values are read from github_private/.env (we recommend using a secure .env)
      }
    }
  ]
};

