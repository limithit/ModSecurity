

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for modsecurity
-- ----------------------------
DROP TABLE IF EXISTS `modsecurity`;
CREATE TABLE `modsecurity` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `mod_id` int(11) DEFAULT NULL COMMENT '标记 0 为 insert 1为update',
  `servername` varchar(255) DEFAULT NULL,
  `SecRule_id` int(255) DEFAULT NULL,
  `clientip` varchar(255) DEFAULT NULL,
  `url` text,
  `attack_type` varchar(255) DEFAULT NULL,
  `at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4347 DEFAULT CHARSET=utf8mb4;
