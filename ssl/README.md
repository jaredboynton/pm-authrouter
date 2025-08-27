# First-Time Certificate Setup

Either run `./generate_cert.sh` or the build scripts will generate certificates here automatically.
This generates your unique SSL certificates that will be used across all builds.

These certificates are:
- Unique to your organization
- Reused for all builds (ensures SHA1 consistency)
- Never regenerated unless explicitly deleted
- Excluded from git (.gitignore)

After running the script, you'll have:
- `identity.getpostman.com.crt` - Your certificate
- `identity.getpostman.com.key` - Your private key (keep secure!)
- `metadata.json` - Certificate metadata including SHA1

**More Info:** See the [Deployment README](../deployment/README.md) for complete build and deployment instructions.
