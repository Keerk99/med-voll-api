CREATE TABLE pacientes(

    id BIGINT NOT NULL auto_increment,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    documento VARCHAR(14) NOT NULL UNIQUE,
    calle VARCHAR(100) NOT NULL,
    distrito VARCHAR(100) NOT NULL,
    complemento VARCHAR(100),
    numero VARCHAR(20),
    ciudad VARCHAR(100) NOT NULL,
    telefono VARCHAR(20) NOT NULL,
    activo tinyint NOT NULL,

    PRIMARY KEY(id)

);