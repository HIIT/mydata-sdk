-- MySQL Script
-- 09/14/16 10:31:08

REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'mydataaccount'@'%';
DROP USER 'mydataaccount'@'%';
DELETE FROM mysql.user WHERE user='mydataaccount';
FLUSH PRIVILEGES;

CREATE USER 'mydataaccount'@'%' IDENTIFIED BY 'wr8gabrA';
GRANT CREATE TEMPORARY TABLES, DELETE, DROP, INSERT, LOCK TABLES, SELECT, UPDATE ON MyDataAccount.* TO 'mydataaccount'@'%';
FLUSH PRIVILEGES;