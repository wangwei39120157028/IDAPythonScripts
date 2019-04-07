-- phpMyAdmin SQL Dump
-- version 3.4.10.1
-- http://www.phpmyadmin.net
--
-- 主机: localhost:3306
-- 生成日期: 2019 年 04 月 07 日 12:58
-- 服务器版本: 5.5.20
-- PHP 版本: 5.3.10

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- 数据库: `dangerousfunctions`
--

-- --------------------------------------------------------

--
-- 表的结构 `functions`
--

CREATE TABLE IF NOT EXISTS `functions` (
  `gets` varchar(11) NOT NULL COMMENT '最危险',
  `strcpy` varchar(12) NOT NULL COMMENT '很危险',
  `strcat` varchar(12) NOT NULL COMMENT '很危险',
  `sprintf` varchar(12) NOT NULL COMMENT '很危险',
  `scanf` varchar(12) NOT NULL COMMENT '很危险',
  `sscanf` varchar(12) NOT NULL COMMENT '很危险',
  `fscanf` varchar(12) NOT NULL COMMENT '很危险',
  `vfscanf` varchar(12) NOT NULL COMMENT '很危险',
  `vsprintf` varchar(12) NOT NULL COMMENT '很危险',
  `vscanf` varchar(12) NOT NULL COMMENT '很危险',
  `vsscanf` varchar(12) NOT NULL COMMENT '很危险',
  `streadd` varchar(12) NOT NULL COMMENT '很危险',
  `strecpy` varchar(12) NOT NULL COMMENT '很危险',
  `strtrns` varchar(12) NOT NULL COMMENT '危险',
  `realpath` varchar(12) NOT NULL COMMENT '很危险',
  `syslog` varchar(12) NOT NULL COMMENT '很危险',
  `getopt` varchar(12) NOT NULL COMMENT '很危险',
  `getopt_long` varchar(12) NOT NULL COMMENT '很危险',
  `getpass` varchar(12) NOT NULL COMMENT '很危险',
  `getchar` varchar(12) NOT NULL COMMENT '中等危险',
  `fgetc` varchar(12) NOT NULL COMMENT '中等危险',
  `getc` varchar(12) NOT NULL COMMENT '中等危险',
  `read` varchar(12) NOT NULL COMMENT '中等危险',
  `bcopy` varchar(12) NOT NULL COMMENT '低危险',
  `fgets` varchar(12) NOT NULL COMMENT '低危险',
  `memcpy` varchar(12) NOT NULL COMMENT '低危险',
  `snprintf` varchar(12) NOT NULL COMMENT '低危险',
  `strccpy` varchar(12) NOT NULL COMMENT '低危险',
  `strcadd` varchar(12) NOT NULL COMMENT '低危险',
  `strncpy` varchar(12) NOT NULL COMMENT '低危险',
  `vsnprintf` varchar(12) NOT NULL COMMENT '低危险'
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
