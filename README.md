# SymbolSpeak Online

A multi-user version of SymbolSpeak with a shared SQLite database, server-side sessions, hashed passwords, admin-only account creation, and the same custom phrase-to-meaning workflow.

## Important

This is a deployable starter project, not a hosted website. It does **not** create a public URL until you deploy it to a hosting provider. Do not use the earlier single-file HTML demo for real accounts; this version uses server-side authentication.

## Run locally

Requirements: Node.js 20+ and npm.

1. Extract this folder.
2. Copy `.env.example` to `.env`.
3. Set `ADMIN_PASSWORD` to a unique password with at least 12 characters.
4. Set `SESSION_SECRET` to a random value of at least 32 characters.
5. Run:

   ```bash
   npm install
   npm start
   ```

6. Open `http://localhost:3000`, then sign in with the admin username and password you set in `.env`.

Never publish `.env`, database files, or secrets to GitHub.

## Deploy online

Use a host that supports Node.js or Docker and **persistent disk/volume storage**. SQLite stores the shared dictionary in `DATA_DIR`; if the host replaces ephemeral containers without a persistent volume, accounts and meanings may be lost. Configure these environment variables in the host dashboard:

- `NODE_ENV=production`
- `ADMIN_USERNAME=admin` (or your preferred admin username)
- `ADMIN_PASSWORD` = a unique strong password (12+ characters)
- `SESSION_SECRET` = a random secret (32+ characters)
- `DATA_DIR=/data` (or the mount path for your persistent volume)
- `PORT` is usually provided by the host.

Mount a persistent disk at `/data`. Enable HTTPS. Do not deploy with the sample credentials. After deployment, share the HTTPS URL with users; the administrator creates each account from **Manage accounts**.

For a managed host that doesn't support persistent volumes well, use a managed PostgreSQL database instead of SQLite before launch.

## Included features

- Translate exact custom phrases and symbols, including creator attribution
- Create, edit and delete entries with optional category and private/shared visibility
- Shared dictionary across all authenticated users
- Admin-only account creation and removal
- Standard users have basic settings and can change their own password
- Administrators have a premium settings panel for workspace label and default entry visibility
- Admin account creation form shows clear success/error feedback and prevents duplicate submissions
- Password hashes using bcrypt; session cookies are HTTP-only and SameSite=Lax
- Login rate limiting and baseline security headers
- Server-side permission checks for account and dictionary actions

## Before a public production launch

- Add a password reset process (admin-issued temporary password or verified email flow).
- Set a proper session secret and strong admin password; keep both in host secret storage.
- Back up the persistent database regularly.
- Consider PostgreSQL for higher availability/multiple server instances.
- Configure HTTPS and review hosting logs/monitoring.
- Have the administrator create individual accounts; never share one account among multiple people.
