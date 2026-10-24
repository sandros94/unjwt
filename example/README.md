# unjwt example

A minimal h3 app with a JWE refresh-token session and a JWS access-token session that refreshes itself from the former on expiry. Install with any package manager, then:

```sh
npm run dev
curl -X POST localhost:3000/login -H 'content-type: application/json' -d '{"username":"alice","password":"x"}' -c jar.txt
curl -X POST localhost:3000/login -b jar.txt
```
