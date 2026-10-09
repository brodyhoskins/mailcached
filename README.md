# `mailcached`

`mailcached` is a local mail cache sitting in front of any mail provider using [IMAP](https://www.rfc-editor.org/rfc/rfc9051), [JMAP](https://www.rfc-editor.org/rfc/rfc8621), [Exchange ActiveSync](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/) and [SMTP](https://www.rfc-editor.org/rfc/rfc6409). It caches your mail, so mail clients get answers at once.

Your mail client connects to `mailcached`, and mailcached connects to your provider. `mailcached` keeps a local copy of each account's folders and flags, and a cache of the messages that clients read. Clients get folder lists, message lists, moves and flag changes from the local copy. mailcached sends the changes to the provider in the background.

## Usage

```
mailcached [-config file] [-version] [-detect address]
```

In your mail client, set the incoming and outgoing servers to the `mailcached` host and ports with TLS. Use your email provider username and password. A JMAP client needs the session URL, like `https://<mailcached host>:<jmap port>/.well-known/jmap`.

For an Exchange account on an iPhone, enter the address and the password. If the phone does not find the server, enter the `mailcached` hostname as the server. Autodiscover finds mailcached when `autodiscover.<your domain>` points to the `mailcached` host on port 443 with a certificate for that hostname. The ActiveSync listener answers at `/Microsoft-Server-ActiveSync` and `/Autodiscover/Autodiscover.xml`. Most devices connect to port 443 only.

## Configuration

See [examples/mailcached.yaml](file:./examples/mailcached.yaml).

## License

MIT. See [LICENSE](LICENSE).
