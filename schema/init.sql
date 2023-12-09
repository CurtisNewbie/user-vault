
CREATE TABLE IF NOT EXISTS user (
  `id` int unsigned NOT NULL AUTO_INCREMENT COMMENT 'primary key',
  `username` varchar(50) NOT NULL COMMENT 'username',
  `password` varchar(255) NOT NULL COMMENT 'password in hash',
  `salt` varchar(10) NOT NULL COMMENT 'salt',
  `create_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'when the record is created',
  `update_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'when the record is updated',
  `is_disabled` int NOT NULL DEFAULT '0' COMMENT 'whether the user is disabled, 0-normal, 1-disabled',
  `review_status` varchar(25) NOT NULL COMMENT 'Review Status',
  `update_by` varchar(255) NOT NULL DEFAULT '' COMMENT 'who updated this record',
  `create_by` varchar(255) NOT NULL DEFAULT '' COMMENT 'who created this record',
  `is_del` tinyint NOT NULL DEFAULT '0' COMMENT '0-normal, 1-deleted',
  `user_no` varchar(32) NOT NULL COMMENT 'user no',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `user_no` (`user_no`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User';

CREATE TABLE IF NOT EXISTS user_key (
  `id` int unIF NOT EXISTS signed NOT NULL AUTO_INCREMENT COMMENT 'primary key',
  `user_id` int unsigned NOT NULL COMMENT 'user.id',
  `name` varchar(255) NOT NULL DEFAULT '' COMMENT 'name of the key',
  `secret_key` varchar(255) NOT NULL COMMENT 'secret key',
  `expiration_time` datetime NOT NULL COMMENT 'when the key is expired',
  `create_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'when the record is created',
  `create_by` varchar(255) NOT NULL DEFAULT '' COMMENT 'who created this record',
  `update_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'when the record is updated',
  `update_by` varchar(255) NOT NULL DEFAULT '' COMMENT 'who updated this record',
  `is_del` tinyint NOT NULL DEFAULT '0' COMMENT '0-normal, 1-deleted',
  PRIMARY KEY (`id`),
  UNIQUE KEY `secret_key` (`secret_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT="user's key";

CREATE TABLE IF NOT EXISTS access_log (
  `id` int unsigned NOT NULL AUTO_INCREMENT COMMENT 'primary key',
  `access_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'when the user signed in',
  `ip_address` varchar(255) NOT NULL COMMENT 'ip address',
  `username` varchar(255) NOT NULL COMMENT 'username',
  `user_id` int unsigned NOT NULL COMMENT 'primary key of user',
  `url` varchar(255) DEFAULT '' COMMENT 'request url',
  `user_agent` varchar(512) NOT NULL DEFAULT '' COMMENT 'User Agent',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4  COMMENT='access log';