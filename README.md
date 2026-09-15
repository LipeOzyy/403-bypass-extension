![alt image](/img/image.png)

# 403-bypass-extension
Browser Extension (Chrome/Edge/Brave, Manifest V3). Upon encountering an endpoint that returns a 403 Forbidden status code, the extension reads the active tab's endpoint and executes a set of well-known bypass techniques, comparing each response against the baseline.


## Tested Techniques

| Category | Description | Approx. Count |
| --- | --- | --- |
| **Path** | Path manipulation: `%2e`, `%2f`, `..;/`, `//`, `;`, matrix params, **double-encoding** (`%252e`, `%252f`), **unicode/fullwidth** (`／` `．`, `%ef%bc%8f`), **overlong UTF-8** (`%c0%ae`, `%f0%80%80%af`), `%uXXXX` (IIS) | ~106 |
| **Case** | Uppercase/lowercase path permutations (`/ADMIN`, `/Admin`) — case-insensitive routing | ~3 |
| **Encoding** | Whitespace/CRLF/null + `%2500`, `%25%32%65` (recursive encoding) | ~14 |
| **Params** | Query/fragment suffixes appended to the path (`?`, `?..`, `?/./`...) | ~33 |
| **Headers** | ~60 origin/IP spoofing headers: `X-Forwarded-For/Host`, `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, `Fastly-Client-IP`, `X-AppEngine-Trusted-IP-Request`... including **localhost encoding variants** (`::1`, `2130706433`, `0x7f000001`, `127.1`, `0.0.0.0`) | ~87 |
| **Rewrite** | `X-Original-URL` / `X-Rewrite-URL` / `X-Override-URL` — requests the forbidden path via an allowed `/` path (classic IIS/Symfony/Nginx bypass) | ~8 |
| **Methods** | HTTP method switching: `POST/PUT/PATCH/DELETE/HEAD/OPTIONS`, WebDAV (`PROPFIND`, `PURGE`), and probe verbs (`DEBUG`, `TRACK`, `TRACE`, `CONNECT`) | ~13 |


## How to Install (Unpacked)
1. Open chrome://extensions (or edge://extensions).
2. Enable Developer mode (top right corner).
3. Click Load unpacked.
4. Select the 403-bypass-extension folder.
5. Pin the extension to your toolbar. When you encounter a 403 error, click the icon → Start bypass.

## Reference:
[gankd/403bypasser](https://github.com/g4nkd/403bypasser)
