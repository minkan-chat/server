<h1>
  <img title="The minkan server" alt="Logo" src="https://github.com/minkan-chat/brand/blob/c14117873fd209ed9ccd93b3d2617151cf0ee832/assets/3d/logo-borders@512.png" width="256" />
  <br>
  <a href="https://github.com/minkan-chat/server/actions/workflows/ci.yml"><img alt="Rust CI" src="https://github.com/minkan-chat/server/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://app.bors.tech/repositories/36806"><img src="https://bors.tech/images/badge_small.svg" alt="Bors enabled"></a>
  <br>
  The minkan server
</h1>
This repository keeps the backend implementation for the Minkan end-to-end encrypted messenger.

The client talks to this service over a <a href="https://graphql.org/">GraphQL API</a> which is reachable via a ``HTTP POST`` request at ``/graphql``. Both <a href="https://https://www.json.org/json-en.html">Json</a> and <a href="https://cbor.io/">CBOR</a> can be used as encoding formats (though CBOR is much preferred).
<br>
The GraphQL schema is generated from the Rust structure. We have <a href="https://github.com/graphql/graphql-playground">GraphQL Playground</a> built in, so you can browse the docs and write queries.

In order to run this software, you'll need to create a file called ``config.toml``:

| Key             | Value                                                                                                      |
|-----------------|------------------------------------------------------------------------------------------------------------|
| ``db_uri``      | A postgresql url string.                                                                                   |
| ``host_uri``    | The address the server should listen to.                                                                   |
| ``jwt_secret``  | A random hex encoded HS256 secret used by the server to sign it's JWTs.                                    |
| ``server_cert`` | An unprotected OpenPGP certificate for the server armor encoded. It must consist of Curve 25519 keys only. |

You can generate a ``jwt_secret`` on a system with <a href="https://www.openssl.org/">OpenSSL</a> installed by running:

```
openssl rand -hex 32
```

On a system with <a href="https://gnupg.org/">GnuPG</a> installed, you can also generate the ``server_cert``:

```
gpg2 --expert --full-generate-key --allow-freeform-uid
```

Note: You have to be in expert mode (``--expert``).
<br>
Select ``ECC and ECC`` and then ``Curve 25519``. Set key expiry to ``0``.

Example ``config.toml``:

```toml
db_uri = "postgresql://my_user:my_password@my.host.com/my_database"
host_uri = "0.0.0.0:8000"
jwt_secret = "6ff255bdb7e89351457912b3511347c76273943b96e9e7ae26bd0ce6513c917f"
server_cert = """
-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEYQgVSRYJKwYBBAHaRw8BAQdAOBjDQeLTTF4k9+p9BHUWZYiZdLFQnd2koUW4
...
JmXRvnN8owY=
=k0FA
-----END PGP PRIVATE KEY BLOCK-----
"""
```

<h1>License</h1>
This software is licensed under the <a href="https://www.gnu.org/licenses/agpl-3.0.txt">GNU Affero General Public License v3.0</a> or later. If you decide to contribute, you agree to license your contribution under the same license.
