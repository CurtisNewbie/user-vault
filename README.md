# user-vault

User management service written in Go

This project internally uses [miso](https://github.com/curtisnewbie/miso) and [gocommon](https://github.com/curtisnewbie/gocommon).


## Dependencies

- MySQL
- Redis
- RabbitMQ
- Consul
- [GoAuth](http://github.com/curtisnewbie/goauth)


## Prometheus Metrics

- `user_vault_token_exchange_duration`: histogram, used to monitor the duration of each token exchange, time is measured in milliseconds.
- `user_vault_fetch_user_info_duration`: histogram, used to monitor the duration of each user info fetching, time is measured in milliseconds.
