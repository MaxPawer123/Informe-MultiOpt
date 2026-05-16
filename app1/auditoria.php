<?php
// Inicia la sesion si aun no existe.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Conexion y funciones compartidas.
require_once __DIR__ . '/conexion.php';

// Obtiene la IP del cliente de forma segura.
function obtenerIpCliente()
{
    $candidatas = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR',
    ];

    foreach ($candidatas as $clave) {
        if (!empty($_SERVER[$clave])) {
            $raw = explode(',', (string) $_SERVER[$clave]);
            $ip = trim($raw[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }

    return '0.0.0.0';
}

// Registra un evento de auditoria usando mysqli preparado.
function registrarAuditoria(mysqli $conn, $usuario, $accion, $detalle = null)
{
    $usuario = trim((string) $usuario);
    if ($usuario === '') {
        $usuario = 'anon';
    }

    $accion = trim((string) $accion);
    $detalle = $detalle !== null ? trim((string) $detalle) : null;
    $ip = obtenerIpCliente();

    $stmt = $conn->prepare('INSERT INTO auditoria (usuario, accion, detalle, ip) VALUES (?, ?, ?, ?)');
    if (!$stmt) {
        error_log('Auditoria: error en prepare: ' . $conn->error);
        return false;
    }

    $stmt->bind_param('ssss', $usuario, $accion, $detalle, $ip);
    $ok = $stmt->execute();

    if (!$ok) {
        error_log('Auditoria: error en execute: ' . $stmt->error);
    }

    $stmt->close();

    return $ok;
}
