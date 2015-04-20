CREATE SEQUENCE users_id_sequence
       START WITH 1
       INCREMENT BY 1
       NO MAXVALUE
       NO MINVALUE
       CACHE 1;
CREATE TABLE users (name varchar(30) NOT NULL UNIQUE,
       	     	    id integer primary key
		       	       DEFAULT nextval('users_id_sequence'));
CREATE SEQUENCE addrs_id_sequence
       START WITH 1
       INCREMENT BY 1
       NO MAXVALUE
       NO MINVALUE
       CACHE 1;
CREATE TABLE addrs (addr varchar(255) NOT NULL UNIQUE,
       	     	    id integer primary key
		       	       DEFAULT nextval('addrs_id_sequence'));

CREATE TABLE associations (addr_id integer references addrs(id),
       	     		   user_id integer references users(id),
			   unique(addr_id, user_id));

CREATE LANGUAGE plpgsql;

CREATE FUNCTION user_name_to_id(name varchar(30)) RETURNS integer AS $$
DECLARE user_id integer;
BEGIN
    EXECUTE 'SELECT id FROM users where users.name = $1'
            INTO STRICT user_id USING name;
    RETURN user_id;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        BEGIN
	    EXECUTE 'INSERT INTO users (name) VALUES ($1) RETURNING id'
		    INTO user_id USING name;
	    RETURN user_id;
	EXCEPTION
	    WHEN UNIQUE_VIOLATION THEN
		EXECUTE 'SELECT id FROM users where users.name = $1'
		    INTO STRICT user_id USING name;
		RETURN user_id;
	END;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION addr_to_id(addr varchar(255)) RETURNS integer AS $$
DECLARE addr_id integer;
BEGIN
    EXECUTE 'SELECT id FROM addrs where addrs.addr = $1'
	INTO STRICT addr_id USING addr;
    RETURN addr_id;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        BEGIN
	    EXECUTE 'INSERT INTO addrs (addr) VALUES ($1) RETURNING id'
		    INTO addr_id USING addr;
	    RETURN addr_id;
	EXCEPTION
	    WHEN UNIQUE_VIOLATION THEN
		EXECUTE 'SELECT id FROM addrs where addrs.addr = $1'
		    INTO STRICT addr_id USING addr;
		RETURN addr_id;
	END;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION associate_if_missing (name varchar(30), target varchar(255))
       RETURNS boolean AS $$
DECLARE
    user_id integer;
    addr_id integer;
BEGIN
    user_id := user_name_to_id(name);
    addr_id := addr_to_id(target);
    EXECUTE 'INSERT INTO associations (addr_id, user_id) values ($1, $2)'
        USING addr_id, user_id;
    RETURN true;
EXCEPTION
    WHEN UNIQUE_VIOLATION THEN
	return true;
END;
$$ LANGUAGE plpgsql;
