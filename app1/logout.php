<?php
session_start();

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
