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

### The First Admin User

```sql
-- username: admin
-- password: 123456, generated with sha256(password + salt)
-- role: Super Administrator (see goauth)
insert into user_vault.user (username, password, salt, review_status, user_no, role_no) values ('admin', '958d51602bbfbd18b2a084ba848a827c29952bfef170c936419b0922994c0589', '123456', 'APPROVED', 'UE1049787455160320075953', 'role_554107924873216177918');
```