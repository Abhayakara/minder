DROP TABLE associations;
DROP TABLE users;
DROP SEQUENCE users_id_sequence;
DROP TABLE addrs;
DROP SEQUENCE addrs_id_sequence;
DROP FUNCTION user_name_to_id(name varchar(30));
DROP FUNCTION addr_to_id(addr varchar(255));
DROP FUNCTION associate_if_missing (name varchar(30), target varchar(255));
