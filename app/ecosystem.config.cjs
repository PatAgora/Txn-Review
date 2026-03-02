module.exports = {
  apps: [
    {
      name: 'transaction-review-tool',
      script: 'python',
      args: 'app.py',
      cwd: '/home/user/webapp',
      env: {
        FLASK_ENV: 'development',
        FLASK_APP: 'app.py',
        PORT: 3000
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork'
    }
  ]
}
