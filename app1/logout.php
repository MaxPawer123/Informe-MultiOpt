<?php
session_start();
require_once __DIR__ . "/multiotp_helper.php";
require_once __DIR__ . "/auditoria.php";

// Auditoria de cierre de sesion.
$usuarioSesion = mfa_current_user($_SESSION);
registrarAuditoria($conn, $usuarioSesion, 'LOGOUT', 'Cierre de sesion');

// Limpiamos tanto la sesion temporal como la autenticacion final.
unset(
	$_SESSION['mfa_pending_user'],
	$_SESSION['mfa_pending_started_at'],
	$_SESSION['mfa_authenticated'],
	$_SESSION['mfa_user'],
	$_SESSION['mfa_authenticated_at'],
	$_SESSION['usuario']
);

session_unset();
session_destroy();
header("Location: login.php");
exit();
?>
