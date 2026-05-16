CREATE TABLE IF NOT EXISTS auditoria (
    id INT NOT NULL AUTO_INCREMENT,

    usuario VARCHAR(100) NOT NULL,

    accion VARCHAR(255) NOT NULL,

    detalle TEXT NULL,

    ip VARCHAR(45) NOT NULL,

    fecha DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_usuario (usuario),

    INDEX idx_fecha (fecha)

) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_0900_ai_ci;