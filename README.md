# Whitelist Censor Service

A standalone censoring service, whitelist-style. Centrally-mangaged, synchronized, offline-friendly. Only intended for personal use between projects.

# About

Todo

# FAQ

## Why not designate a master server and communicate locally over intranet?

- My personal servers are restarted daily, which means downtime or potential silent "failed-to-start"s.
- My personal servers are running livestreams that involve mouse+keyboard manipulation, which would make maintenance difficult and create unneccesary downtime.
- A remote server is already required for other tasks, might as well utilize it.
- Would still have to create a client in addition to the server, at best would just have less responsibilities and overhead.

## Why not directly route requests to a (central) remote HTTP server/database?

- Latency and unneccesary bandwidth.
- Public facing databases/HTTP servers are prime targets for automated fuzzing and attacks.
- There would be additional security work required both initially and over time, as maintenance.

## Why not use a VPN?

- Additional work, adds a failure point. The VPN may fail, disconnect, or land in a broken state, which would require additional work to account for, even if its unlikely to happen.

## Why not use a delta update system instead of downloading entire files?

- Guaranteed consistency, I don't want to create additional work for a validation system. The files themselves are quite small in the grand scheme of things.

## Why not use RPC, Websockets, or a message broker like ZeroMQ?

- I don't have enough experience in them to create a system as quickly as I would this one.
- May require authentication or additional security work.
- REST requests are easy to do in any language, any of the mentioned solutions require more integration code and/or more work.

## Your solution doesn't seem very secure

- The data is not sensitive.
- My concerns about security arise from malicious attacks or high volume/unauthorized requests. I believe this to be an adequate, low-time-cost solution. Security by obscurity is acceptable for this project.

## Your solution is inefficient/against standards

- This project is a solution to an annoyance in a hobby project, I don't see a benefit to anyone if I were to use my time to make it efficient and up-to-standard.
- This project is based on a prototype I extracted from a hobby project, which was already a throwaway solution in the first place.
